# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Read-only original-UID/process/socket proof; never signal an unknown process.

Linux proc status/stat/cgroup and proc/net/tcp formats are described by the
kernel's filesystems/proc, networking/proc_net_tcp and cgroup-v2 documentation.
Caller supplies the container ID and expected argv only after Docker's immutable
image, labels, user and mount configuration have been independently qualified.
"""
import os
from pathlib import Path
import re
import stat
from storage import require

PROC = Path('/proc')


def bounded(path, maximum=65536):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as stream:
        value = stream.read(maximum + 1)
    require(len(value) <= maximum, 'process observation exceeds its bound')
    return value


def status(pid):
    value = {}
    wanted = {b'Uid', b'Gid', b'Pid', b'Groups', b'NoNewPrivs', b'CapInh', b'CapPrm', b'CapEff', b'CapAmb'}
    for line in bounded(PROC / str(pid) / 'status').splitlines():
        key, separator, raw = line.partition(b':')
        if key not in wanted: continue  # Process names are arbitrary bytes, not authority.
        name = key.decode('ascii')
        require(separator and name not in value, 'ambiguous process status')
        value[name] = raw.decode('ascii').split()
    for name in ('Uid', 'Gid'):
        require(len(value.get(name, [])) == 4 and all(v.isdecimal() for v in value[name]),
                'process numeric ownership is unavailable')
        value[name] = tuple(int(v) for v in value[name])
    require(value.get('Pid') == [str(pid)], 'process status PID differs')
    return value


def identity(pid):
    require(type(pid) is int and 1 < pid < 2**31, 'invalid native process identity')
    raw = bounded(PROC / str(pid) / 'stat', 16384)
    close = raw.rfind(b')')
    require(raw.startswith(str(pid).encode() + b' (') and close > 0, 'invalid process stat identity')
    fields = raw[close + 1:].decode('ascii').split()
    require(len(fields) >= 20 and len(fields[0]) == 1 and fields[1].isdecimal() and fields[19].isdecimal(),
            'process start identity is unavailable')
    return {'pid': pid, 'start_time': int(fields[19]), 'parent': int(fields[1]), 'state': fields[0]}


def owned_pids(uids):
    require(isinstance(uids, set) and uids and all(type(uid) is int and uid > 0 for uid in uids),
            'original process UID set is missing')
    entries = list(PROC.iterdir()); require(len(entries) <= 1000000, 'process namespace exceeds its bound')
    result = set()
    for entry in entries:
        if not entry.name.isdecimal(): continue
        pid = int(entry.name)
        try: info = status(pid)
        except FileNotFoundError: continue
        if uids.intersection(info['Uid']): result.add(pid)
    return result


def quiescent(records):
    require(isinstance(records, dict) and records, 'missing original shutdown identities')
    uids = {record['uid'] for record in records.values()}
    require(not owned_pids(uids), 'an original validator process remains outside verified shutdown')


def snapshot(pid, account, executable, argv, cgroups):
    before = identity(pid); value = status(pid)
    require(before['state'] not in ('Z', 'X') and before['start_time'] > 0
            and value['Uid'] == (account['uid'],) * 4 and value['Gid'] == (account['gid'],) * 4,
            'native process UID/GID or lifetime differs')
    require('Groups' in value and all(group.isdecimal() for group in value['Groups'])
            and {int(v) for v in value['Groups']} <= {account['gid']}, 'native process has supplementary authority')
    require(value.get('NoNewPrivs') == ['1'] and all(value.get(name) and len(value[name]) == 1
            and re.fullmatch('0+', value[name][0]) for name in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb')),
            'native process retains unexpected capabilities or privilege transitions')
    path = PROC / str(pid)
    require(os.readlink(path / 'exe') == executable, 'native process executes an unqualified binary')
    actual = bounded(path / 'cmdline').split(b'\0')
    if actual and actual[-1] == b'': actual.pop()
    require(actual == [value.encode() for value in argv], 'native command line differs from its immutable configuration')
    group = bounded(path / 'cgroup', 16384).decode('ascii').strip()
    require(group.startswith('0::') and '\n' not in group and group[3:] in cgroups,
            'native process does not belong to its qualified cgroup')
    network = (path / 'ns/net').stat()
    require(stat.S_ISREG(network.st_mode) and network.st_ino == (PROC / '1/ns/net').stat().st_ino,
            'native process is not in the expected host network namespace')
    require(identity(pid) == before, 'native PID was replaced during process qualification')
    return dict(before, uid=account['uid'], gid=account['gid'], executable=executable,
                cgroup=group[3:], network_namespace=network.st_ino)


def listeners(pid, uid, ports):
    require(isinstance(ports, tuple) and ports and all(type(port) is int and 0 < port < 65536 for port in ports),
            'invalid reserved listener set')
    before = identity(pid); path = PROC / str(pid)
    descriptors = list((path / 'fd').iterdir())
    require(len(descriptors) <= 131072, 'native descriptor set exceeds its bound')
    sockets = set()
    for descriptor in descriptors:
        try: value = os.readlink(descriptor)
        except FileNotFoundError: continue
        match = re.fullmatch(r'socket:\[([0-9]+)\]', value)
        if match: sockets.add(int(match[1]))
    found = {port: [] for port in ports}
    for family in ('tcp', 'tcp6'):
        rows = bounded(path / 'net' / family, 8 * 1024 * 1024).decode('ascii').splitlines()
        require(rows, 'native socket table is unavailable')
        for row in rows[1:]:
            fields = row.split()
            if not fields: continue
            require(len(fields) >= 10 and re.fullmatch('[0-9A-Fa-f]+:[0-9A-Fa-f]{4}', fields[1]),
                    'invalid native socket table row')
            local, port = fields[1].rsplit(':', 1); port = int(port, 16)
            if port not in found or fields[3] != '0A': continue
            require(family == 'tcp' and local == '0100007F' and fields[7] == str(uid) and fields[9].isdecimal(),
                    'reserved native listener is public or belongs to another UID')
            found[port].append(int(fields[9]))
    require(all(len(values) == 1 and values[0] in sockets for values in found.values()),
            'reserved loopback listener does not belong to the exact native PID')
    require(identity(pid) == before, 'native PID changed while proving listener ownership')
    return {str(port): values[0] for port, values in found.items()}


def container_members(account, parent, group):
    """Every process with the original node UID stays in the proved container.

    A manually launched writer or Docker-exec shell is not silently ignored.
    Native JIT/prover children are qualified from the immutable image paths.
    """
    allowed = {'/usr/local/bin/nitro', '/usr/local/bin/jit', '/usr/local/bin/prover', '/usr/local/bin/validator'}
    pids = owned_pids({account['uid']})
    require(parent in pids, 'original native process disappeared')
    for pid in pids:
        try:
            before = identity(pid); info = status(pid); path = PROC / str(pid)
            require(info['Uid'] == (account['uid'],)*4 and info['Gid'] == (account['gid'],)*4
                    and 'Groups' in info and all(v.isdecimal() for v in info['Groups'])
                    and {int(v) for v in info['Groups']} <= {account['gid']}
                    and info.get('NoNewPrivs') == ['1']
                    and all(info.get(key) and len(info[key]) == 1 and re.fullmatch('0+', info[key][0])
                            for key in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb')),
                    'original node UID has a process with unexpected authority')
            require(os.readlink(path/'exe') in allowed
                    and bounded(path/'cgroup', 16384).decode('ascii').strip() == '0::'+group,
                    'original node UID has an orphan or unqualified native writer')
            require(identity(pid) == before, 'native child PID was replaced during qualification')
        except FileNotFoundError:
            require(pid != parent, 'original native process disappeared')
    return pids
