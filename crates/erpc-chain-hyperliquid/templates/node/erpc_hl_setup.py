# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Public native configuration and dedicated account/storage validation."""
import grp
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
from erpc_hl_common import ROOT, CONFIG, HELPERS, atomic, digest, execute, fsync_dir, json_bytes, read, require, unique_json
import erpc_hl_public as public
import erpc_hl_units as units

NATIVE = 'erpc-hyperliquid'
GATEWAY = 'erpc-hyperliquid-rpc'
HOME = ROOT / 'home'
MOUNTINFO = Path('/proc/self/mountinfo')
ROOT_UID = 0


def storage_mounts():
    """The operator may mount ROOT itself, but never a managed subtree."""
    with MOUNTINFO.open() as source:
        contents = source.read(8_388_609)
    require(len(contents) <= 8_388_608, 'kernel mount information exceeds its bound')
    for row in contents.splitlines():
        fields = row.split()
        require(len(fields) >= 10 and '-' in fields, 'kernel mount information is unavailable')
        name = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), fields[4])
        path = Path(name)
        require(path.is_absolute() and ROOT not in path.parents,
                'mount the complete managed root; nested data or bootstrap mounts are refused')


def account_plan(planned):
    require(isinstance(planned, dict) and set(planned) == {NATIVE, GATEWAY}
            and all(isinstance(item, dict) and set(item) == {'uid', 'gid'}
                    and type(item['uid']) is int and type(item['gid']) is int
                    and 100 <= item['uid'] <= 999 and item['uid'] == item['gid']
                    for item in planned.values())
            and planned[NATIVE]['uid'] != planned[GATEWAY]['uid'], 'invalid dedicated identity reservation')


def account_snapshot():
    users, groups = pwd.getpwall(), grp.getgrall()
    require(len(users) <= 100000 and len(groups) <= 100000, 'account namespace exceeds its bound')
    return users, groups


def account_slot(name, chosen, missing=False):
    user, group = lookup(pwd.getpwnam, name), lookup(grp.getgrnam, name)
    users, groups = account_snapshot()
    named = [item for item in users if item.pw_name == name]
    named_groups = [item for item in groups if item.gr_name == name]
    def user_fields(value):
        return None if value is None else (value.pw_name,value.pw_uid,value.pw_gid,value.pw_dir,value.pw_shell)
    def group_fields(value):
        return None if value is None else (value.gr_name,value.gr_gid,frozenset(value.gr_mem))
    require(len(named) <= 1 and len(named_groups) <= 1
            and user_fields(user) == user_fields(named[0] if named else None)
            and user_fields(user) == user_fields(lookup(pwd.getpwuid, chosen['uid']))
            and group_fields(group) == group_fields(named_groups[0] if named_groups else None)
            and group_fields(group) == group_fields(lookup(grp.getgrgid, chosen['gid']))
            and not any((item.pw_uid == chosen['uid'] or item.pw_gid == chosen['gid'])
                        and item.pw_name != name for item in users)
            and not any(item.gr_gid == chosen['gid'] and item.gr_name != name for item in groups),
            'reserved identity differs across direct and enumerated NSS authority')
    if group is not None:
        require(group.gr_gid == chosen['gid'] and set(group.gr_mem) <= {name}, 'reserved group changed or is shared')
    if user is not None:
        require(group is not None and user.pw_uid == chosen['uid'] and user.pw_gid == chosen['gid']
                and user.pw_dir == (str(HOME) if name == NATIVE else '/nonexistent')
                and user.pw_shell == '/usr/sbin/nologin'
                and set(os.getgrouplist(name, chosen['gid'])) == {chosen['gid']},
                'dedicated service account differs from its original profile')
    require(missing or (user is not None and group is not None), 'original dedicated service identity is missing')
    return user, group


def accounts(expected):
    account_plan(expected)
    for name, chosen in expected.items(): account_slot(name, chosen)
    return expected


def lookup(function, value):
    try:
        return function(value)
    except KeyError:
        return None


def provision_accounts(state):
    """Durable numeric reservation precedes every fallible NSS mutation."""
    names = (NATIVE, GATEWAY)
    if (state.directory / 'accounts.json').exists():
        result = accounts(state.get('accounts.json'))
        require(state.get('account-reservation.json') == result,
                'completed identities differ from the original reservation')
        persist_accounts(state, result, completed=True)
        return result
    reservation = state.directory / 'account-reservation.json'
    if not reservation.exists():
        users, groups = account_snapshot()
        require(all(lookup(pwd.getpwnam, name) is None and lookup(grp.getgrnam, name) is None
                    for name in names) and not any(item.pw_name in names for item in users)
                and not any(item.gr_name in names for item in groups), 'unknown dedicated account cannot be adopted')
        used = {item.pw_uid for item in users} | {item.pw_gid for item in users} | {item.gr_gid for item in groups}
        available = [number for number in range(999, 99, -1)
                     if number not in used and lookup(pwd.getpwuid, number) is None and lookup(grp.getgrgid, number) is None]
        require(len(available) >= 2, 'two unused dedicated system identities are required')
        state.put('account-reservation.json', {name: {'uid': number, 'gid': number}
                                              for name, number in zip(names, available[:2])})
    planned = state.get('account-reservation.json')
    account_plan(planned)
    for name, chosen in planned.items(): account_slot(name, chosen, missing=True)
    # A visible rename after a failed directory fsync is not durable authority.
    # Re-establish that authority on every retry before changing any NSS entry.
    persist_accounts(state, planned)
    for name, home in ((NATIVE, str(HOME)), (GATEWAY, '/nonexistent')):
        chosen = planned[name]
        user, group = account_slot(name, chosen, missing=True)
        if group is None:
            execute(['/usr/sbin/groupadd', '--system', '--gid', str(chosen['gid']), name])
        user, _ = account_slot(name, chosen, missing=True)
        if user is None:
            execute(['/usr/sbin/useradd', '--system', '--uid', str(chosen['uid']), '--gid', str(chosen['gid']),
                     '--no-create-home', '--home-dir', home, '--shell', '/usr/sbin/nologin', name])
        account_slot(name, chosen)
    result = accounts(planned)
    state.put('accounts.json', result)
    persist_accounts(state, result, completed=True)
    return result


def persist_accounts(state, planned, completed=False):
    state.put('account-reservation.json', planned)
    if completed:
        state.put('accounts.json', planned)
    for directory in (state.directory, *state.directory.parents):
        fsync_dir(directory)


def native_directories(identity):
    """Caller has verified the root-owned host contract and stopped every writer."""
    storage_mounts()
    parent = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    device = os.fstat(parent).st_dev
    try:
        for name in ('home', 'hl', 'data'):
            try:
                os.mkdir(name, 0o700, dir_fd=parent)
            except FileExistsError:
                pass
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            try:
                info = os.fstat(child)
                require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, identity['uid'])
                        and info.st_dev == device
                        and not info.st_mode & 0o022, 'native data directory is indirect or foreign')
                os.fchown(child, identity['uid'], identity['gid'])
                os.fchmod(child, 0o700)
                os.fsync(child)
                os.fsync(parent)
            except Exception:
                os.close(child)
                raise
            os.close(parent)
            parent = child
    finally:
        os.close(parent)


def storage_descriptor(identity=None):
    """Open every actual native path component without following a user link."""
    probe = ROOT
    while not probe.exists():
        require(not probe.is_symlink(), 'native filesystem path is indirect')
        probe = probe.parent
    descriptor = os.open(probe, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        root_info = os.fstat(descriptor)
        require(root_info.st_uid == ROOT_UID and not root_info.st_mode & 0o022,
                'native filesystem root is not protected')
        if probe != ROOT:
            return descriptor, False
        device = root_info.st_dev
        for name in ('home', 'hl', 'data'):
            try:
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            except FileNotFoundError:
                return descriptor, False
            try:
                info = os.fstat(child)
                require(info.st_dev == device and identity is not None
                        and info.st_uid == identity['uid'] and info.st_gid == identity['gid']
                        and info.st_mode & 0o7777 == 0o700,
                        'native path device, original identity or privacy changed')
            except Exception:
                os.close(child)
                raise
            os.close(descriptor)
            descriptor = child
        return descriptor, True
    except Exception:
        os.close(descriptor)
        raise


def capacity(identity=None, validator=False):
    storage_mounts()
    # The documented native tree includes public outputs under hl/data and
    # private native files under hl/hyperliquid_data. Measure their shared
    # mounted volume, not only the output-log subdirectory.
    data = HOME / 'hl'
    descriptor, complete = storage_descriptor(identity)
    try:
        stats = os.fstatvfs(descriptor)
        allocated = 0
        if complete:
            measured = execute(['/usr/bin/du', '--one-file-system', '--summarize', '--block-size=1', str(data)]).stdout.split()
            require(measured and measured[0].isdigit(), 'native allocation cannot be established')
            allocated = int(measured[0])
            check, present = storage_descriptor(identity)
            try:
                before, after = os.fstat(descriptor), os.fstat(check)
                require(present and (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino),
                        'native database path changed during capacity inspection')
            finally:
                os.close(check)
    finally:
        os.close(descriptor)
    required = max(200_000_000_000 if validator else 100_000_000_000,
                   (900_000_000_000 if validator else 450_000_000_000) - allocated)
    require(stats.f_blocks * stats.f_frsize >= (980_000_000_000 if validator else 490_000_000_000)
            and stats.f_bavail * stats.f_frsize >= required,
            'native filesystem does not meet its role-specific total and remaining sync capacity')
    return {'available': stats.f_bavail * stats.f_frsize, 'required': required}


def public_gnupg(release):
    """Create a read-only public verification keyring, never a signing key."""
    target = CONFIG / 'gnupg'
    stage = CONFIG / '.gnupg-stage'
    record = CONFIG / 'public-keyring.json'
    source = digest(read(release / 'publisher.asc'))
    if target.exists() or target.is_symlink():
        info = target.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == ROOT_UID and info.st_mode & 0o7777 == 0o755,
                'publisher keyring directory changed')
        receipt = unique_json(read(record))
        require(receipt['source'] == source and set(receipt['files']) ==
                {str(target / name) for name in ('pubring.kbx', 'trustdb.gpg')},
                'publisher keyring receipt differs')
        require(set(path.name for path in target.iterdir()) == {'pubring.kbx', 'trustdb.gpg'},
                'unexpected publisher keyring entries')
        for name, expected in receipt['files'].items():
            require(Path(name).lstat().st_mode & 0o7777 == 0o444
                    and digest(read(Path(name))) == expected, 'publisher keyring content or reader permissions changed')
        return receipt['files']
    if stage.exists() or stage.is_symlink():
        info = stage.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == ROOT_UID and info.st_mode & 0o7777 in (0o700, 0o755),
                'unowned publisher staging directory')
        shutil.rmtree(stage)
    stage.mkdir(mode=0o700)
    execute(['/usr/bin/gpg', '--batch', '--no-options', '--no-autostart', '--homedir', str(stage),
             '--import', str(release / 'publisher.asc')])
    execute(['/usr/bin/gpg', '--batch', '--no-options', '--no-autostart', '--homedir', str(stage),
             '--check-trustdb'])
    receipt = {}
    for name in ('pubring.kbx', 'trustdb.gpg'):
        path = stage / name
        data = read(path)
        atomic(path, data, 0o444)
        receipt[str(target / name)] = digest(data)
    # GPG import may create empty private-key/cache directories. No private key
    # was supplied; only the two explicit public verification files are exposed.
    for path in stage.iterdir():
        if path.name not in ('pubring.kbx', 'trustdb.gpg'):
            require(not path.is_symlink(), 'unexpected publisher keyring link')
            if path.is_dir():
                require(not any(path.iterdir()), 'unexpected signing material in public keyring')
                path.rmdir()
            else:
                require(path.name == 'pubring.kbx~', 'unexpected publisher keyring artifact')
                path.unlink()
    stage.chmod(0o755)
    fsync_dir(stage)
    # A crash after directory publication can reconstruct the exact completed
    # public trust without importing a replacement key or accepting new bytes.
    atomic(record, json_bytes({'source': source, 'files': receipt}))
    os.rename(stage, target)
    fsync_dir(CONFIG)
    return receipt


def allow(values):
    require(isinstance(values, list) and len(values) <= 64, 'invalid RPC access list')
    result = []
    for value in values:
        require(isinstance(value, str), 'invalid RPC network')
        result.append(str(ipaddress.ip_network(value, strict=True)))
    return sorted(set(result))


def configuration(contract, profile, rpc_allow, peers):
    public.public_ipv4(contract['public_ip'])
    expected = 'Mainnet' if contract['network'] == 'mainnet' else 'Testnet'
    require(profile['chain'] == expected, 'public profile differs from the reserved network')
    result = {
        'visor.json': json.dumps({'chain': profile['chain']}, sort_keys=True).encode() + b'\n',
        'public-ip': contract['public_ip'].encode() + b'\n',
        'gateway.json': json.dumps({'allow': allow(rpc_allow)}, sort_keys=True).encode() + b'\n',
    }
    if contract['network'] == 'mainnet':
        require(isinstance(peers, dict) and set(peers) == {'chain', 'root_node_ips'}
                and peers['chain'] == 'Mainnet' and isinstance(peers['root_node_ips'], list)
                and 0 < len(peers['root_node_ips']) <= 64, 'mainnet needs qualified public root peers')
        for peer in peers['root_node_ips']:
            require(isinstance(peer, dict) and set(peer) == {'Ip'}, 'invalid native root peer')
            public.public_ipv4(peer['Ip'])
        result['gossip.json'] = json.dumps(peers, sort_keys=True).encode() + b'\n'
    else:
        require(peers is None, 'testnet uses the documented native discovery defaults')
    return result


def install_configuration(contract, profile, rpc_allow, peers, identities, mode='follower'):
    """Publish only public configuration while startup is durably fenced."""
    content = configuration(contract, profile, rpc_allow, peers)
    receipt = {}
    for name, data in content.items():
        path = CONFIG / name
        atomic(path, data, 0o644)
        receipt[str(path)] = digest(data)
    for name, value in units.render(contract, profile['supervisor'],identities,mode).items():
        path = Path('/etc/systemd/system') / name
        data = value.encode()
        atomic(path, data, 0o644)
        receipt[str(path)] = digest(data)
    fsync_dir(CONFIG)
    return receipt
