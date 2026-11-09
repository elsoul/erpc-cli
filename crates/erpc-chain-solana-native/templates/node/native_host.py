# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Prepare a fresh dedicated host without formatting or adopting legacy data."""
import os
from pathlib import Path
import platform
import pwd
import re
import stat
import subprocess
from native_files import read, require, root_directory, sync_directory, sync_file
from native_contract import MOUNTS, validate
from native_state import State
import native_accounts as accounts
import native_mounts as mounts
import native_process as process
import native_tuning as tuning
import native_platform

HOME = Path('/var/lib/erpc-solana')
STATE = HOME / 'state'
OS_RELEASE = Path('/etc/os-release')
VENDOR_RELEASE = Path('/usr/lib/os-release')
CPUINFO = Path('/proc/cpuinfo')
CONFIG_ROOT = Path('/etc/erpc')
LEGACY = ('solv.service', 'faithful.service', 'of1-index-sync.service')


def command(argv, allowed=(0,)):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=30, check=False, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    require(result.returncode in allowed and len(result.stdout) <= 65536, 'native host inspection failed')
    return result.stdout.decode()


def operating_system():
    return native_platform.operating_system(OS_RELEASE,VENDOR_RELEASE,read,root_directory)


def platform_facts(role,network,run=command):
    return native_platform.platform_facts(role,network,run,operating_system,CPUINFO)


def preflight(role, network, volumes, run=command):
    return {'platform': platform_facts(role, network, run), 'volumes': mounts.inspect_volumes(volumes, initial=True)}


def refuse_legacy(run=command):
    try: pwd.getpwnam('solv')
    except KeyError: pass
    else: raise ValueError('existing solv identity requires explicit verified migration')
    for unit in (*LEGACY, 'erpc-solana.service'):
        state = run(['/usr/bin/systemctl', 'show', unit, '--property=LoadState', '--value'], allowed=(0, 1)).strip()
        require(state == 'not-found', 'existing native or legacy service requires explicit recovery or migration')


def empty_volume(path):
    for entry in path.iterdir():
        info = entry.lstat()
        require(entry.name == 'lost+found' and stat.S_ISDIR(info.st_mode) and info.st_uid == 0
                and not info.st_mode & 0o022 and not any(entry.iterdir()), 'unowned native volume data cannot be adopted')


def data_directories(state, contract, plan):
    node = plan['node']
    expected = {'contract': contract, 'uid': node['uid'], 'gid': node['gid']}
    ready = state.directory / 'data.json'
    if ready.exists():
        require(state.get('data.json') == expected, 'native data ownership receipt differs')
    else:
        process.assert_quiescent(node['uid'])
        intent = state.directory / 'data-intent.json'
        if intent.exists(): require(state.get('data-intent.json') == expected, 'native data preparation belongs to another owner')
        else:
            require(not any((mount / 'data').exists() or (mount / 'data').is_symlink() for mount in MOUNTS.values()),
                    'unreceipted native data cannot be adopted')
            state.put('data-intent.json', expected)
        sync_file(intent); sync_directory(state.directory)
        for mount in MOUNTS.values():
            path = mount / 'data'
            if not path.exists(): path.mkdir(mode=0o700)
            info = path.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, node['uid'])
                    and info.st_mode & 0o7777 == 0o700 and not any(path.iterdir()),
                    'interrupted native data preparation contains unowned data')
            os.chown(path, node['uid'], node['gid'])
            sync_directory(path); sync_directory(mount)
        process.assert_quiescent(node['uid'])
        state.put('data.json', expected)
    for mount in MOUNTS.values():
        info = (mount / 'data').lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == node['uid'] and info.st_gid == node['gid']
                and info.st_mode & 0o7777 == 0o700, 'native data directory ownership changed')
        sync_directory(mount / 'data'); sync_directory(mount)
    sync_file(ready); sync_directory(state.directory)


def allocated_data(state, contract, run=command):
    """Only original private payload allocation can offset initial sync capacity."""
    result = dict.fromkeys(MOUNTS, 0)
    if not (state.directory / 'data.json').exists(): return result
    node = accounts.verify(state, contract)['node']
    require(state.get('data.json') == {'contract': contract, 'uid': node['uid'], 'gid': node['gid']},
            'native data allocation belongs to another account')
    for kind, mount in MOUNTS.items():
        path = mount / 'data'; before = path.lstat()
        require(stat.S_ISDIR(before.st_mode) and before.st_uid == node['uid'] and before.st_gid == node['gid']
                and before.st_mode & 0o7777 == 0o700, 'native allocation directory authority changed')
        if not any(path.iterdir()): continue
        raw = run(['/usr/bin/du', '--one-file-system', '--summarize', '--block-size=1', '--', str(path)])
        fields = raw.strip().split(maxsplit=1)
        require(len(fields) == 2 and re.fullmatch('[0-9]{1,19}', fields[0]) and fields[1] == str(path),
                'native data allocation observation differs')
        after = path.lstat()
        require((before.st_dev, before.st_ino, before.st_uid, before.st_gid, before.st_mode)
                == (after.st_dev, after.st_ino, after.st_uid, after.st_gid, after.st_mode),
                'native allocation directory changed during inspection')
        result[kind] = int(fields[0])
    return result


def capacity(state, contract, run=command):
    state.owner(contract)
    observed = mounts.inspect(contract)
    allocated = allocated_data(state, contract, run)
    for kind, observation in observed.items():
        minimum = max(mounts.HEADROOM, mounts.MIN_TOTAL[kind] * 9 // 10 - allocated[kind])
        require(observation['free_bytes'] >= minimum, 'native filesystem lacks remaining initial synchronization capacity')
    return observed


def prepare(contract, run=command):
    validate(contract)
    platform_facts('rpc' if contract['profile'] == 'agave-native-rpc' else 'validator', contract['network'], run)
    root_directory(HOME.parent)
    if HOME.exists() or HOME.is_symlink():
        root_directory(HOME)
        require(HOME.lstat().st_mode & 0o005 == 0o005, 'native working directory is not traversable by its isolated account')
    if STATE.exists() or STATE.is_symlink():
        root_directory(STATE)
        require(STATE.lstat().st_mode & 0o7777 == 0o700, 'native lifecycle state is not private')
    fresh = not (STATE / 'owner.json').exists()
    if fresh: mounts.inspect(contract, initial=True)
    if not fresh:
        previous = State(STATE)
        # Complete only the original, strictly checked partial reservation.
        # This restores halt/fence metadata; capacity is still checked before
        # account creation, data preparation or kernel configuration.
        previous.reserve(contract)
        capacity(previous, contract, run)
    if fresh:
        refuse_legacy(run)
        if CONFIG_ROOT.exists() or CONFIG_ROOT.is_symlink():
            root_directory(CONFIG_ROOT)
            require(not any(CONFIG_ROOT.iterdir()), 'fresh native host cannot adopt another managed profile')
        for path in (HOME, *[Path(home) for role, (_, home) in accounts.SPECS.items() if role != 'node']):
            if path.exists() or path.is_symlink():
                root_directory(path)
                entries = list(path.iterdir())
                if path == HOME and entries == [STATE]:
                    root_directory(STATE)
                    require(not any(STATE.iterdir()), 'unowned native state cannot be adopted')
                else:
                    require(not entries, 'unowned native account home cannot be adopted')
        for mount in MOUNTS.values(): empty_volume(mount)
    # Do not create the node's working directory as an incidental private
    # ancestor of STATE: systemd chdirs after dropping to the original node UID.
    root_directory(HOME, create=True, mode=0o755)
    require(HOME.lstat().st_mode & 0o005 == 0o005, 'native working directory is not traversable by its isolated account')
    root_directory(STATE, create=True, mode=0o700)
    require(STATE.lstat().st_mode & 0o7777 == 0o700, 'native lifecycle state is not private')
    state = State(STATE)
    state.reserve(contract)
    plan = accounts.ensure(state, contract)
    if contract['profile'] == 'agave-native-rpc':
        import native_gateway_account
        native_gateway_account.ensure(state, contract)
    data_directories(state, contract, plan)
    import native_source_floor
    native_source_floor.initialize(state, contract)
    tuning.configure(state, contract)
    return {'prepared': True, 'contract': contract, 'accounts': plan}
