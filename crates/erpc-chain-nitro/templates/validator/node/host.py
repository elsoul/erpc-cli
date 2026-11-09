# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original data/account preparation on a qualified dedicated Nitro host."""
import scope
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shlex
import shutil
import stat
import subprocess
import sys
import accounts
import storage
import volumes
from state import State, contract
from storage import directory, read, require, sync_directory, synchronize

ROOT = Path(scope.ROOT)
DATA = ROOT / 'data'
HELPERS = Path('/usr/local/lib/erpc')/scope.NAMESPACE
CONFIG = Path('/etc/erpc')/scope.NAMESPACE
CUSTODY = Path('/etc/credstore.encrypted')/scope.NAMESPACE
UPSTREAM_CUSTODY = Path('/etc/credstore.encrypted')/(scope.NAMESPACE+'-l1')
TLS_CUSTODY = Path('/etc/credstore.encrypted')/(scope.NAMESPACE+'-tls')
UNITS = Path('/etc/systemd/system')
RUNTIME = Path('/run')/('erpc-'+scope.NAMESPACE)
FIREWALL = Path('/etc/erpc')/scope.FAMILY
FIREWALL_HELPER = Path('/usr/local/lib/erpc/rpc-firewall.py')
NAMES = tuple(scope.SERVICES.values())
DOCKER = Path('/usr/bin/docker')
BUDGET = 6_000_000_000_000
HEADROOM = 200_000_000_000


def command(argv, allowed=(0,), maximum=1048576, timeout=30):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout, check=False,
                            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    require(result.returncode in allowed and len(result.stdout) <= maximum, 'validator host observation failed')
    return result.stdout


def platform_facts(run=command):
    require(sys.version_info[:2] == (3, 12), 'active BoLD profile requires the Ubuntu24.04 Python3.12 interpreter')
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64',
            'active BoLD profile requires qualified Linux x86-64')
    path = Path('/etc/os-release'); directory(path.parent)
    if path.is_symlink():
        require(path.lstat().st_uid == 0, 'untrusted OS release selector')
        target = Path(os.readlink(path))
        if not target.is_absolute(): target = path.parent / target
        require(os.path.normpath(target) == '/usr/lib/os-release', 'OS release leaves its vendor namespace')
        path = Path('/usr/lib/os-release')
    directory(path.parent)
    release = {}
    for line in read(path, 16384).decode().splitlines():
        key, separator, value = line.partition('=')
        if key not in ('ID', 'VERSION_ID'): continue
        values = shlex.split(value)
        require(separator and len(values) == 1 and key not in release, 'ambiguous OS release')
        release[key] = values[0]
    require(release == {'ID': 'ubuntu', 'VERSION_ID': '24.04'}, 'active BoLD profile requires Ubuntu24.04')
    version = run(['/usr/bin/systemctl', '--version']).decode().splitlines()
    require(version and re.match(r'^systemd 255(?: |$)', version[0]), 'active BoLD credentials require systemd255')
    memory = os.sysconf('SC_PHYS_PAGES') * os.sysconf('SC_PAGE_SIZE')
    cores = os.cpu_count() or 0
    # ERPC provision policy for co-located execution and native WASM validation;
    # this is not a protocol minimum or a performance acceptance benchmark.
    require(memory >= 120 * 1024**3 and cores >= 16, 'insufficient dedicated execution/validation capacity')
    return {'systemd': 255, 'logical_cpus': cores, 'memory_bytes': memory}


def preflight(run=command):
    facts = platform_facts(run)
    uuid, free = filesystem(run=run)
    require(free >= BUDGET, 'insufficient initial qualified validator synchronization space')
    return dict(facts, data_uuid=uuid, free_bytes=free)


def protected_tree(path, missing=False):
    if not path.exists() and not path.is_symlink():
        require(missing, 'managed validator namespace is missing')
        ancestor = path.parent
        while not ancestor.exists() and not ancestor.is_symlink(): ancestor = ancestor.parent
        directory(ancestor)
        return
    directory(path)
    pending = [path]
    while pending:
        for child in pending.pop().iterdir():
            info = child.lstat()
            if stat.S_ISDIR(info.st_mode): directory(child); pending.append(child)
            else: read(child, 8 * 1024 * 1024)


def namespaces():
    for path in (HELPERS, CONFIG, CUSTODY, UPSTREAM_CUSTODY, TLS_CUSTODY, RUNTIME, FIREWALL): protected_tree(path, missing=True)
    if FIREWALL_HELPER.exists() or FIREWALL_HELPER.is_symlink(): read(FIREWALL_HELPER, 1048576)
    else:
        ancestor = FIREWALL_HELPER.parent
        while not ancestor.exists() and not ancestor.is_symlink(): ancestor = ancestor.parent
        directory(ancestor)
    directory(UNITS)
    for name in NAMES:
        file = UNITS / name
        if file.exists() or file.is_symlink(): read(file, 262144)
        protected_tree(UNITS / (name + '.d'), missing=True)


def no_nested_mounts(probe, run=command):
    raw=run(['/usr/bin/findmnt','--json','--submounts','--target',str(probe),'--output','TARGET'],maximum=8*1024*1024)
    value=json.loads(raw);rows=value.get('filesystems')
    require(isinstance(rows,list) and rows,'validator mount topology is unavailable')
    pending=list(rows);count=0;data_mounts=0;root_mounts=0
    while pending:
        item=pending.pop();count+=1
        require(count<=100000 and isinstance(item,dict) and isinstance(item.get('target'),str),
                'validator mount topology exceeds its bound')
        target=Path(item['target']);require(target.is_absolute(),'invalid mounted target')
        require(not (target!=DATA and DATA in target.parents),
                'nested validator data mounts, including same-device binds, are not qualified')
        require(not (ROOT in target.parents and target != DATA),
                'unexpected mount beneath original validator receipt root')
        if target==DATA:data_mounts+=1
        if target==ROOT:root_mounts+=1
        children=item.get('children',[]);require(isinstance(children,list),'invalid mounted descendants')
        pending.extend(children)
    require(data_mounts<=1 and root_mounts<=1,'stacked validator data or receipt-root mounts are not qualified')


def filesystem_identity(path, run=command):
    probe = path
    while not probe.exists() and not probe.is_symlink(): probe = probe.parent
    if probe == DATA:
        directory(ROOT)
        require(stat.S_ISDIR(probe.lstat().st_mode), 'validator data is not a real directory')
    else: directory(probe)
    before = probe.lstat()
    raw = run(['/usr/bin/findmnt', '--json', '--target', str(probe), '--output', 'UUID,FSTYPE,OPTIONS'])
    require(len(raw) <= 16384, 'filesystem observation exceeds its bound')
    value = json.loads(raw); rows = value.get('filesystems')
    require(isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict), 'ambiguous validator filesystem')
    row = rows[0]
    identified = volumes.shape({key: row.get(key) for key in ('uuid', 'fstype')})
    require(isinstance(row.get('options'), str) and 'rw' in row['options'].split(','),
            'validator requires a writable original filesystem')
    after = probe.lstat()
    require(directory_identity(before) == directory_identity(after), 'filesystem changed during observation')
    return dict(identified, device=before.st_dev)


def filesystem(expected=None, run=command):
    probe = DATA
    while not probe.exists() and not probe.is_symlink(): probe = probe.parent
    no_nested_mounts(probe, run)
    observed = filesystem_identity(DATA, run)
    require(expected is None or observed['uuid'] == expected['data_uuid'], 'original validator data filesystem was replaced')
    return observed['uuid'], shutil.disk_usage(probe).free


def capacity(state, expected, run=command):
    _, free = filesystem(expected, run)
    allocated = 0
    if (state.root / 'data.json').exists():
        current = volumes.verify(state, expected, run)
        layout = state.get('storage-layout.json')
        require(set(layout) in ({'contract', 'root', 'data'}, {'contract', 'root', 'data', 'filesystems'}) and layout['contract'] == expected
                and volumes.same(ROOT.lstat(), layout['root'], current['root']['device']), 'original storage root was replaced')
        record = accounts.verify(state, expected)['node']
        saved = state.get('data.json')
        require(set(saved) == {'contract', 'uid', 'gid', 'directory'} and saved['contract'] == expected
                and saved['uid'] == record['uid'] and saved['gid'] == record['gid'],
                'validator data receipt belongs to another original account')
        info = DATA.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == record['uid'] and info.st_gid == record['gid']
                and info.st_mode & 0o7777 == 0o700 and volumes.same(info, saved['directory'], current['data']['device']),
                'validator data authority changed')
        if any(DATA.iterdir()):
            raw = run(['/usr/bin/du', '--one-file-system', '--summarize', '--block-size=1', '--exclude=lost+found', '--', str(DATA)])
            fields = raw.decode().strip().split(maxsplit=1)
            require(len(fields) == 2 and re.fullmatch('[0-9]{1,19}', fields[0]) and fields[1] == str(DATA),
                    'validator data allocation is unavailable')
            after = DATA.lstat()
            require((info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode) ==
                    (after.st_dev, after.st_ino, after.st_uid, after.st_gid, after.st_mode),
                    'validator data changed during allocation inspection')
            allocated = int(fields[0])
    require(free >= max(HEADROOM, BUDGET - allocated), 'validator lacks initial synchronization space or operating reserve')
    return {'free_bytes': free, 'original_allocated_bytes': allocated}


def directory_identity(info):
    return {'device': info.st_dev, 'inode': info.st_ino}


def empty_volume(path, recovery=False):
    """Bind a prepared empty root-owned volume without removing lost+found."""
    directory(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        original = os.fstat(descriptor)
        require(stat.S_ISDIR(original.st_mode) and original.st_uid == storage.ROOT_UID
                and not original.st_mode & 0o022, 'prepared volume is not root protected')
        require(set(os.listdir(descriptor)) <= (set() if recovery else {'lost+found'}), 'unowned Nitro data cannot be adopted')
        if 'lost+found' in os.listdir(descriptor):
            recovery = os.open('lost+found', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                               dir_fd=descriptor)
            try:
                info = os.fstat(recovery)
                require(info.st_uid == storage.ROOT_UID and not info.st_mode & 0o022
                        and not os.listdir(recovery), 'filesystem recovery directory is not empty and root protected')
                actual = os.stat('lost+found', dir_fd=descriptor, follow_symlinks=False)
                require(directory_identity(actual) == directory_identity(info), 'filesystem recovery directory changed')
            finally: os.close(recovery)
        actual = path.lstat()
        require((actual.st_dev, actual.st_ino, actual.st_uid, actual.st_mode) ==
                (original.st_dev, original.st_ino, original.st_uid, original.st_mode), 'prepared volume changed')
        return volumes.stable(original)
    finally: os.close(descriptor)


def initial_layout(state_files=()):
    """Only storage preparation is adoptable before the original owner exists."""
    if not ROOT.exists() and not ROOT.is_symlink(): return
    directory(ROOT)
    descriptor = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        original = os.fstat(descriptor)
        names = set(os.listdir(descriptor))
        require(names <= {'data', 'lost+found', *state_files}, 'existing Nitro ownership cannot be converted to validator')
        for name in names:
            if name in state_files: read(ROOT/name)
            elif name == 'data': empty_volume(DATA)
            else: empty_volume(ROOT/name, recovery=True)
        require(directory_identity(ROOT.lstat()) == directory_identity(original), 'original storage root changed')
    finally: os.close(descriptor)


def fresh(expected=None, run=command):
    for foreign in scope.FOREIGN_ROOTS:
        require(not Path(foreign).exists() and not Path(foreign).is_symlink(),
                'another Nitro role or network has retained storage; no cross-adoption is allowed')
    if expected is not None: contract(expected)
    namespaces()
    for name in ('erpc-nitro', 'erpc-nitro-upstreams'):
        try: pwd.getpwnam(name)
        except KeyError: pass
        else: raise ValueError('existing Nitro follower account requires explicit role migration')
    for name in NAMES:
        observed = run(['/usr/bin/systemctl', 'show', name, '--property=LoadState', '--value'], allowed=(0, 1)).strip()
        require(observed == b'not-found', 'existing Nitro service cannot be adopted')
    for path in (HELPERS, CONFIG, CUSTODY, UPSTREAM_CUSTODY, TLS_CUSTODY, RUNTIME, FIREWALL):
        require(not path.exists() or not any(path.iterdir()), 'unknown validator material cannot be adopted')
    if DOCKER.exists():
        import container
        require(container.find(run=run) is None, 'unowned named native container cannot be adopted')
    initial_layout()


def reserve_layout(state, expected, run=command):
    """Persist prepared storage identity before any dedicated NSS mutation."""
    state.current_owner(expected)
    path = state.root/'storage-layout.json'
    if not path.exists():
        # No account/data intent may predate the original storage reservation.
        initial_layout(('owner.json', 'fence.json'))
        descriptor = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            current_root = os.fstat(descriptor)
            root = volumes.stable(current_root)
            observed = volumes.observations(expected, run)
            require(current_root.st_dev == observed['root']['device'], 'ROOT volume changed before reservation')
            prepared = empty_volume(DATA) if DATA.exists() or DATA.is_symlink() else None
            require(directory_identity(ROOT.lstat()) == directory_identity(current_root), 'storage root changed before reservation')
            state.put('storage-layout.json', {'contract': expected, 'root': root, 'data': prepared,
                      'filesystems': {key: volumes.persistent(observed[key]) for key in ('root', 'data')}})
        finally: os.close(descriptor)
    volumes.reserve(state, expected, run)
    current = volumes.verify(state, expected, run)
    saved = state.get('storage-layout.json')
    require(set(saved) in ({'contract', 'root', 'data'}, {'contract', 'root', 'data', 'filesystems'}) and saved['contract'] == expected
            and volumes.same(ROOT.lstat(), saved['root'], current['root']['device']), 'original storage layout was replaced')
    synchronize(path)
    if not (state.root/'data-intent.json').exists() and not (state.root/'data.json').exists():
        actual = empty_volume(DATA) if DATA.exists() or DATA.is_symlink() else None
        require((actual is None and saved['data'] is None) or (actual is not None and saved['data'] is not None
                and volumes.inode(actual) == volumes.inode(saved['data'])), 'prepared original data volume changed before initialization')
    return saved


def data(state, expected, records, quiescent, run=command):
    current = volumes.verify(state, expected, run)
    record = records['node']; wanted = {'contract': expected, 'uid': record['uid'], 'gid': record['gid']}
    if not (state.root / 'data.json').exists():
        quiescent()
        intent = state.root / 'data-intent.json'
        if not intent.exists():
            prepared = empty_volume(DATA) if DATA.exists() or DATA.is_symlink() else None
            state.put('data-intent.json', dict(wanted, directory=prepared))
        saved = state.get('data-intent.json')
        require(set(saved) == {*wanted, 'directory'} and all(saved[key] == value for key, value in wanted.items()),
                'validator data intent belongs to another owner')
        synchronize(intent)
        if saved['directory'] is None:
            if not DATA.exists(): DATA.mkdir(mode=0o700)
            saved = dict(saved, directory=empty_volume(DATA))
            state.put('data-intent.json', saved)
        synchronize(intent)
        descriptor = os.open(DATA, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(descriptor)
            require(volumes.same(info, saved['directory'], current['data']['device']) and info.st_uid in (storage.ROOT_UID, record['uid'])
                    and not info.st_mode & 0o022 and set(os.listdir(descriptor)) <= {'lost+found'},
                    'interrupted validator data contains unowned or replaced content')
            if info.st_uid == storage.ROOT_UID: empty_volume(DATA)
            require(volumes.same(DATA.lstat(), saved['directory'], current['data']['device']), 'prepared data was replaced')
            os.fchown(descriptor, record['uid'], record['gid']); os.fchmod(descriptor, 0o700); os.fsync(descriptor)
            require(volumes.same(DATA.lstat(), saved['directory'], current['data']['device']), 'data publication was redirected')
        finally: os.close(descriptor)
        sync_directory(ROOT); quiescent()
        state.put('data.json', dict(wanted, directory=saved['directory']))
    saved = state.get('data.json')
    require(set(saved) == {*wanted, 'directory'} and all(saved[key] == value for key, value in wanted.items()),
            'original validator data authority differs')
    info = DATA.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == record['uid'] and info.st_gid == record['gid']
            and info.st_mode & 0o7777 == 0o700 and volumes.same(info, saved['directory'], current['data']['device']),
            'validator data ownership or original directory changed')
    sync_directory(DATA); sync_directory(ROOT); synchronize(state.root / 'data.json')


def initialize(expected, quiescent, run=command, account_run=accounts.command):
    """Called under both ERPC operation and native-controller locks."""
    contract(expected); facts = platform_facts(run); namespaces()
    state = State(ROOT)
    if not (ROOT / 'owner.json').exists(): fresh(expected, run)
    else: directory(ROOT); state.owner(expected)
    available = capacity(state, expected, run)
    directory(ROOT, create=True, mode=0o755)
    state.reserve(expected, lambda: initial_layout(('owner.json',)))
    reserve_layout(state, expected, run)
    current = volumes.verify(state, expected, run)
    if not (ROOT/'data.json').exists() and (DATA.exists() or DATA.is_symlink()):
        intent = state.get('data-intent.json') if (ROOT/'data-intent.json').exists() else None
        if intent is None or intent.get('directory') is None:
            empty_volume(DATA)
        else:
            descriptor = os.open(DATA, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                info = os.fstat(descriptor)
                require(intent.get('contract') == expected and volumes.same(info, intent['directory'], current['data']['device'])
                        and info.st_uid in (storage.ROOT_UID, intent.get('uid')) and not info.st_mode & 0o022
                        and set(os.listdir(descriptor)) <= {'lost+found'}, 'partial original data authority changed')
                if 'lost+found' in os.listdir(descriptor):
                    recovery = os.open('lost+found', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor)
                    try:
                        meta = os.fstat(recovery)
                        require(meta.st_uid == storage.ROOT_UID and not meta.st_mode & 0o022 and not os.listdir(recovery),
                                'original filesystem recovery directory changed')
                    finally: os.close(recovery)
                require(volumes.same(DATA.lstat(), intent['directory'], current['data']['device']), 'partial data directory changed')
            finally: os.close(descriptor)
    records = accounts.ensure(state, expected, account_run)
    data(state, expected, records, lambda: quiescent(records), run)
    return {'initialized': True, 'contract': expected, 'accounts': records, 'capacity': available, 'platform': facts}
