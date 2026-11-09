# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""An operator selects a pre-existing partition. ERPC never repartitions or wipes it."""
import json
import os
from pathlib import Path
import re
import stat
from erpc_monad_common import require, execute

MIN_DEVICE_BYTES = 1_900_000_000_000  # usable partition on a nominal 2 TB device
SAMPLE_BYTES = 4 * 1024 * 1024


def partuuid(value):
    require(isinstance(value, str) and re.fullmatch(
        '[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', value),
        'require a canonical GPT partition PARTUUID')
    return value


def flatten(nodes):
    for node in nodes:
        yield node
        yield from flatten(node.get('children', []))


def qualify_inventory(records, uuid, device, major_minor, swaps):
    """Pure policy separated from Linux collection for inert failure testing."""
    nodes = list(flatten(records))
    matches = [n for n in nodes if n.get('partuuid') == uuid]
    require(len(matches) == 1, 'PARTUUID is missing or duplicated')
    n = matches[0]
    require(n.get('path') == device and re.fullmatch('/dev/nvme[0-9]+n[0-9]+p[0-9]+', device),
            'only a physical NVMe partition is supported')
    require(n.get('type') == 'part' and n.get('maj:min') == major_minor,
            'device identity changed during inspection')
    require(n.get('ro') is False and n.get('log-sec') == 512
            and isinstance(n.get('size'), int) and n['size'] >= MIN_DEVICE_BYTES,
            'partition must be writable, at least 2 TB and use 512-byte logical sectors')
    require(not n.get('fstype') and not n.get('uuid') and not any(n.get('mountpoints') or []),
            'partition has a filesystem, filesystem identifier or mount')
    parent_name = n.get('pkname')
    parents = [p for p in nodes if p.get('path') in (parent_name, '/dev/' + str(parent_name))]
    require(len(parents) == 1, 'physical parent disk is ambiguous')
    parent = parents[0]
    require(parent.get('type') == 'disk' and not parent.get('ro') and parent.get('serial')
            and not parent.get('fstype') and not any(parent.get('mountpoints') or []),
            'parent must be an unmounted physical disk with a serial number')
    # Reject an OS disk even when the selected spare partition itself is unmounted.
    related = list(flatten([parent]))
    require(all(not any(x.get('mountpoints') or []) and x.get('path') not in swaps
                and x.get('type') in ('disk', 'part') for x in related),
            'parent disk contains a mount, swap or mapped device')
    require(isinstance(n.get('start'), int) and n['start'] > 0, 'invalid partition geometry')
    return {'partuuid': uuid, 'path': device, 'major_minor': major_minor,
            'start': n['start'], 'size': n['size'], 'logical_sector': n['log-sec'],
            'physical_sector': n['phy-sec'], 'disk_serial': str(parent['serial']),
            'disk_size': parent['size'], 'parent': parent['path']}


def inspect(uuid, *, blank=False):
    uuid = partuuid(uuid)
    link = Path('/dev/disk/by-partuuid') / uuid
    device = link.resolve(strict=True)
    s = device.stat()
    require(stat.S_ISBLK(s.st_mode), 'selected PARTUUID is not a block device')
    major_minor = str(os.major(s.st_rdev)) + ':' + str(os.minor(s.st_rdev))
    fields = 'PATH,TYPE,PARTUUID,SIZE,START,LOG-SEC,PHY-SEC,RO,MOUNTPOINTS,FSTYPE,UUID,PKNAME,SERIAL,MAJ:MIN'
    result = execute(['/usr/bin/lsblk', '--json', '--bytes', '--output', fields])
    swaps = {line.split()[0] for line in Path('/proc/swaps').read_text().splitlines()[1:]}
    record = qualify_inventory(json.loads(result.stdout)['blockdevices'], uuid, str(device), major_minor, swaps)
    for dev in (device, Path(record['parent'])):
        holders = Path('/sys/class/block') / dev.name / 'holders'
        require(holders.is_dir() and not list(holders.iterdir()), 'device has kernel holders')
    # Mount/swap checks above are repeated before every native write and startup.
    if blank:
        signatures = execute(['/usr/sbin/wipefs', '--json', '--no-act', str(device)])
        require(not json.loads(signatures.stdout).get('signatures'), 'existing device signatures')
        fd = os.open(device, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            require(os.fstat(fd).st_rdev == s.st_rdev, 'device replaced during inspection')
            for offset in (0, record['size'] - SAMPLE_BYTES):
                data = os.pread(fd, SAMPLE_BYTES, offset)
                require(len(data) == SAMPLE_BYTES and not any(data), 'device edge samples are not blank')
        finally:
            os.close(fd)
    return record


def same_device(expected, observed):
    # Kernel device numbers and names may change across reboots. The stable
    # contract is PARTUUID + parent serial + complete partition/disk geometry.
    keys = ('partuuid', 'start', 'size', 'logical_sector', 'physical_sector', 'disk_serial', 'disk_size')
    require(all(expected.get(key) == observed.get(key) for key in keys),
            'selected physical partition no longer matches the reserved device')
