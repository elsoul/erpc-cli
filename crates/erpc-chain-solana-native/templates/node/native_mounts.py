# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Validate operator-mounted disks without formatting, mounting or deleting data."""
import os
from pathlib import Path
import re
import shutil
import stat
from native_contract import MOUNTS, validate, validate_volumes
from native_files import require, root_directory

# The host's mount table, PID 1's. systemd binds each ReadWritePaths entry in a
# unit's mount namespace even for its '+' commands, so from a start condition
# /proc/self would show the data directories as nested mounts of themselves.
MOUNTINFO = Path('/proc/1/mountinfo')
UUIDS = Path('/dev/disk/by-uuid')
# Formatted capacity policy for nominal 1 TB / 1 TB / 500 GB volumes. This
# allowance for filesystem overhead is an ERPC policy, not an upstream quote.
MIN_TOTAL = {'accounts': 900_000_000_000, 'ledger': 900_000_000_000, 'snapshots': 450_000_000_000}
HEADROOM = 64 * 1024**3


def unescape(value):
    translations = {'040': ' ', '011': '\t', '012': '\n', '134': '\\'}
    require(not re.search(r'\\(?!040|011|012|134)', value), 'unsupported mountinfo escape')
    return re.sub(r'\\(040|011|012|134)', lambda match: translations[match[1]], value)


def parse(text):
    require(isinstance(text, str) and len(text) <= 4 * 1024 * 1024, 'mount namespace exceeds its bound')
    result, ids = [], set()
    for line in text.splitlines():
        fields = line.split()
        require(len(fields) >= 10 and fields.count('-') == 1, 'invalid Linux mount metadata')
        separator = fields.index('-')
        require(separator >= 6 and len(fields) == separator + 4
                and fields[0].isdigit() and fields[1].isdigit()
                and re.fullmatch('[0-9]+:[0-9]+', fields[2]), 'invalid Linux mount identity')
        require(fields[0] not in ids, 'duplicate Linux mount identity')
        ids.add(fields[0])
        root, point = unescape(fields[3]), unescape(fields[4])
        require(point.startswith('/') and '..' not in point.split('/') and '.' not in point.split('/'),
                'noncanonical Linux mountpoint')
        result.append({'id': fields[0], 'device': tuple(map(int, fields[2].split(':'))),
                       'root': root, 'point': Path(point), 'options': fields[5].split(','),
                       'fs': fields[separator+1], 'source': unescape(fields[separator+2]),
                       'super_options': fields[separator+3].split(',')})
    require(result, 'empty Linux mount namespace')
    return result


def read_mounts():
    # A controller entrypoint first requires Linux/root; no operator-supplied
    # metadata path is accepted in production.
    with MOUNTINFO.open('rb') as stream:
        data = stream.read(4 * 1024 * 1024 + 1)
    require(len(data) <= 4 * 1024 * 1024, 'mount namespace exceeds its bound')
    return parse(data.decode('utf-8'))


def selected_mounts(mounts):
    selected = {}
    for kind, path in MOUNTS.items():
        matches = [entry for entry in mounts if entry['point'] == path]
        require(len(matches) == 1, 'required native filesystem is missing or overmounted')
        entry = matches[0]
        require(entry['root'] == '/' and entry['fs'] in ('ext4', 'xfs')
                and 'rw' in entry['options'] and 'ro' not in entry['options']
                and 'rw' in entry['super_options'] and 'ro' not in entry['super_options'],
                'native data must use a writable dedicated ext4 or xfs filesystem')
        require(not any(path in other['point'].parents for other in mounts), 'nested native data mount refused')
        require(sum(other['device'] == entry['device'] for other in mounts) == 1,
                'native filesystem has another mount or bind alias')
        selected[kind] = entry
    require(len({entry['device'] for entry in selected.values()}) == len(MOUNTS), 'native data filesystems share a device')
    return selected


def inspect(contract, initial=False):
    validate(contract)
    return inspect_volumes(contract['volumes'], initial)


def inspect_volumes(volumes, initial=False):
    """Read-only preflight can run before a new identity or inventory is created."""
    validate_volumes(volumes)
    root_directory(UUIDS)
    before = selected_mounts(read_mounts())
    observed = {}
    for kind, entry in before.items():
        path = MOUNTS[kind]
        root_directory(path)
        # UUID lookup intentionally follows the root-managed udev symlink to a
        # block device. Only its device number, never its text, is trusted here.
        device = (UUIDS / volumes[kind]).stat()
        info = path.stat()
        require(stat.S_ISBLK(device.st_mode)
                and (os.major(device.st_rdev), os.minor(device.st_rdev)) == entry['device']
                and (os.major(info.st_dev), os.minor(info.st_dev)) == entry['device'],
                'mounted device differs from the reserved filesystem UUID')
        usage = shutil.disk_usage(path)
        require(usage.total >= MIN_TOTAL[kind], 'native data filesystem is below the selected capacity policy')
        minimum = MIN_TOTAL[kind] * 9 // 10 if initial else HEADROOM
        require(usage.free >= minimum, 'native data filesystem has insufficient free space')
        observed[kind] = {'uuid': volumes[kind], 'mount_id': entry['id'],
                          'device': list(entry['device']), 'fs': entry['fs'],
                          'total_bytes': usage.total, 'free_bytes': usage.free}
    require(selected_mounts(read_mounts()) == before, 'native mount namespace changed during validation')
    return observed
