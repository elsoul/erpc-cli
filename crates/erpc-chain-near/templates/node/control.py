#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""NEAR ownership and lifecycle boundary; RPC mode never loads a validator key."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time
import tempfile
import pwd
import grp
import urllib.request

# BEGIN ERPC TRUSTED IMPORTS
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
# Embedded verbatim in helpers that need sibling modules. Startup uses -I;
# only this checked directory is added, after the standard-library paths.
def trusted_imports(directory):
    import os
    import stat
    import sys
    path = os.fspath(directory)
    if not os.path.isabs(path):
        raise ValueError('helper directory must be an absolute path')
    current = os.path.sep
    for part in path.split(os.path.sep)[1:]:
        if part in ('', '.'):
            continue
        if part == '..':
            # The component being left was already checked as a real root-only
            # directory. Never normalize away an unchecked symlink ancestor.
            current = os.path.dirname(current)
            continue
        current = os.path.join(current, part)
        info = os.lstat(current)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('helper ancestors must be real root-owned directories')
    path = current
    if path == os.path.sep:
        raise ValueError('the filesystem root is not a helper directory')
    # Do not create root0700 bytecode caches before an unprivileged helper
    # imports the same module. Existing readable caches remain fully checked.
    sys.dont_write_bytecode = True
    pending = [path]
    while pending:
        for child in os.scandir(pending.pop()):
            info = child.stat(follow_symlinks=False)
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError('helper modules must be writable only by root')
            if stat.S_ISDIR(info.st_mode):
                if (child.name == '__pycache__'
                        and not os.access(child.path, os.X_OK, effective_ids=True)):
                    # No traversal means Python cannot read any cached module
                    # here and must use the checked source. Denied listing alone
                    # (e.g. mode0711) is not sufficient for this exception.
                    continue
                pending.append(child.path)
            elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError('helper modules cannot be links or special files')
    if path not in sys.path:
        sys.path.append(path)
# END ERPC TRUSTED IMPORTS

ROOT_UID = 0
HELPERS = "/usr/local/lib/erpc/near"

CONTAINER = 'erpc-near'
UNIT = 'near-node.service'
PINS = {
    'mainnet': {
        'version': '2.14.0', 'commit': 'bc4e9e8cfb03d9e82f027883055624e18576993e',
        'image': 'nearprotocol/nearcore@sha256:6c4f7a681b8920f0d9ec5256bac6aac00f657afd9de6c5a73b72e178f0c30082',
        'genesis_hash': 'EPnLgE7iEq9s7yTkos96M3cWymH5avBAPm3qx3NXqR8H',
        'genesis_height': 9820210,
        'genesis_sha256': '501446da246048d0378979bea8e9f21a3a8f5ecd5fd1a6e2a709ace1ab6883a3',
        'config_sha256': '274f8e66714d6d45830d90853fba0e4ea75309d96b3b0680bfc8f968e8106337',
    },
    'testnet': {
        'version': '2.14.0-rc.6', 'commit': 'd37c9e9ed3412dfab319e2e56bde24fd38e62ef1',
        'image': 'nearprotocol/nearcore@sha256:873963dceb8d14d94d35995cf51f1b98d2e6e8c85b031b69ace0664e9ce737ca',
        'genesis_hash': 'FWJ9kR6KFWoyMoNjpLXXGHeuiy7tEY6GmoFeCA5yuc6b',
        'genesis_height': 42376888,
        'genesis_sha256': '8a9d7a103b23d18879a73448fbb79bde547064c481e8f5d9db011478a671f48d',
        'config_sha256': 'a1c93a945b1827e952a4793e99d2b8c138f9f43865761c97254435d1f5027cef',
    },
}

# Recognize this original pending release only for an explicit forward update.
# It is not a new deployment target or permission to open a newer database.
PREVIOUS_PINS = {
    'mainnet': {'version':'2.13.4','commit':'44f7ae6cd7ef08bab604e20a473bf77e35d4c993',
                'image':'nearprotocol/nearcore@sha256:79e66f5ecaba010d3d71e5e1bd6e032d755b7666d3810224a8a5624920355519'},
}


class Refused(Exception):
    pass


def block_age(value):
    """Parse the native UTC RFC3339 nanosecond timestamp on every supported Python."""
    from datetime import datetime, timezone
    if not isinstance(value, str): raise Refused('missing block timestamp')
    found = re.fullmatch(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?(?:Z|\+00:00)', value)
    if not found: raise Refused('invalid native UTC block timestamp')
    normalized = found[1] + '.' + ((found[2] or '') + '000000')[:6] + '+00:00'
    return (datetime.now(timezone.utc) - datetime.fromisoformat(normalized)).total_seconds()


class Control:
    def __init__(self, root=Path('/'), run=subprocess.run):
        self.root, self.run = root, run
        self.directory = self.path('/etc/erpc/near')
        self.home = self.path('/var/lib/near')

    def path(self, value):
        return self.root / value.lstrip('/')

    def command(self, *argv, check=True, data=None):
        result = self.run(list(argv), input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'}, check=False)
        if check and result.returncode:
            raise Refused('required host operation failed')
        return result

    def docker(self, *argv, **kwargs):
        return self.command('docker', '--host', 'unix:///var/run/docker.sock',
                            '--config', '/etc/erpc/near/docker', *argv, **kwargs)

    @staticmethod
    def digest(value):
        return hashlib.sha256(value).hexdigest()

    def directory_guard(self, path, create=False, mode=0o755):
        """Never normalize through or repair an existing foreign namespace."""
        relative = path.relative_to(self.root)
        current = self.root
        for part in (None, *relative.parts):
            if part is not None: current = current / part
            try:
                info = current.lstat()
            except FileNotFoundError:
                if not create: return False
                current.mkdir(mode=mode)
                info = current.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != ROOT_UID or info.st_mode & 0o022:
                raise Refused('protected directory is indirect, foreign or writable')
        return True

    def file_info(self, info, private=False, limit=None):
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != ROOT_UID
                or info.st_nlink != 1 or info.st_mode & (0o077 if private else 0o022)
                or (limit is not None and info.st_size > limit)):
            raise Refused('protected file is indirect, foreign, writable or oversized')

    def file_guard(self, path, private=False):
        self.directory_guard(path.parent)
        try: info = path.lstat()
        except FileNotFoundError: return False
        self.file_info(info, private)
        return True

    def tree_guard(self, path, private=False):
        if not self.directory_guard(path): return
        pending = [path]
        count = 0
        while pending:
            for child in pending.pop().iterdir():
                count += 1
                if count > 100000: raise Refused('protected namespace exceeds its bound')
                info = child.lstat()
                if stat.S_ISDIR(info.st_mode):
                    self.directory_guard(child)
                    pending.append(child)
                else:
                    self.file_info(info, private)

    def protected_paths(self, initial=False):
        disabled = self.path('/etc/near/disabled-validator.json')
        if disabled.exists() or disabled.is_symlink():
            raise Refused('RPC follower cannot adopt a validator credential')
        for path, private in (('/etc/erpc/near', True), ('/etc/near', False), (HELPERS, False)):
            self.tree_guard(self.path(path), private)
        self.file_guard(self.path('/usr/local/lib/erpc/rpc-firewall.py'))
        for name in ('near-node.key', 'near-node.pending', 'near-validator.key'):
            self.file_guard(self.path('/etc/credstore.encrypted/' + name), private=True)
        credentials = self.path('/etc/credstore.encrypted')
        if credentials.exists():
            for child in credentials.iterdir():
                if child.name.startswith(('near-validator.previous.', '.near-validator.')):
                    self.file_guard(child, private=True)
        for unit in (UNIT, 'erpc-near-firewall.service'):
            file = self.path('/etc/systemd/system/' + unit)
            exists = self.file_guard(file)
            directory = file.with_name(file.name + '.d')
            dropins = self.directory_guard(directory)
            if initial and (exists or dropins):
                raise Refused('unknown existing NEAR service configuration')
            if dropins:
                for child in directory.iterdir():
                    if child.name not in ('50-erpc-firewall-guard.conf', '50-erpc-firewall-guard.conf.new'):
                        raise Refused('unknown NEAR service override')
                    self.file_guard(child)

    def state_path(self, name):
        if not isinstance(name, str) or not re.fullmatch(r'[a-z][a-z0-9.-]{0,79}', name):
            raise Refused('invalid managed state name')
        self.directory_guard(self.directory)
        return self.directory / name

    def read(self, name):
        path = self.state_path(name)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as file:
            self.file_info(os.fstat(file.fileno()), private=True, limit=65536)
            raw = file.read(65537)
            self.file_info(os.fstat(file.fileno()), private=True, limit=65536)
        if len(raw) > 65536: raise Refused('oversized managed state')
        return json.loads(raw)

    def write(self, name, value):
        path = self.state_path(name)
        self.file_guard(path, private=True)
        payload = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
        if len(payload) > 65536: raise Refused('oversized managed state')
        fd, pending = tempfile.mkstemp(prefix='.' + name + '.', dir=self.directory)
        temporary = Path(pending)
        try:
            with os.fdopen(fd, 'wb') as file:
                os.fchmod(file.fileno(), 0o600)
                self.file_info(os.fstat(file.fileno()), private=True)
                file.write(payload)
                file.flush()
                os.fsync(file.fileno())
            os.replace(temporary, path)
            self.sync_directory(self.directory)
        finally:
            temporary.unlink(missing_ok=True)

    def sync_directory(self, path):
        self.directory_guard(path)
        parent = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(parent)
        finally: os.close(parent)

    def remove(self, name):
        path = self.state_path(name)
        self.file_guard(path, private=True)
        path.unlink(missing_ok=True)
        self.sync_directory(self.directory)

    def publication(self, expected, firewall=False):
        self.contract(expected)
        self.account(expected)
        source = Path(__file__).parent / '../rpc-firewall.py' if firewall else Path(__file__)
        target = '/usr/local/lib/erpc/rpc-firewall.py' if firewall else HELPERS + '/control.py'
        if self.file_digest(source) != self.file_digest(self.path(target)):
            raise Refused('installed controller differs from the sealed carried source')
        if not firewall:
            sibling = 'near_validator.py'
            if self.file_digest(source.parent / sibling) != self.file_digest(self.path(HELPERS + '/' + sibling)):
                raise Refused('installed validator helper differs from the sealed carried source')

    @staticmethod
    def expected(value):
        fields = {'owner', 'network', 'role', 'genesis_hash'}
        if isinstance(value, dict) and value.get('role') == 'validator':
            fields |= {'validator_account', 'owner_account', 'staking_public_key', 'commission_basis_points'}
        if not isinstance(value, dict) or set(value) != fields:
            raise Refused('invalid host ownership contract')
        if value['network'] not in PINS or value['role'] not in ('rpc', 'validator'):
            raise Refused('unsupported NEAR network or role')
        if not isinstance(value['owner'], str) or not re.fullmatch('[A-Za-z0-9_-]{1,80}', value['owner']):
            raise Refused('invalid owner identity')
        if value['genesis_hash'] != PINS[value['network']]['genesis_hash']:
            raise Refused('network genesis identity differs')
        if value['role'] == 'validator':
            import near_validator
            try: near_validator.reservation(value)
            except (ValueError, KeyError, TypeError): raise Refused('invalid reserved validator identity') from None
        return value

    def contract(self, expected, initial=False):
        self.expected(expected)
        file = self.directory / 'contract.json'
        self.protected_paths(initial=not file.exists())
        if file.exists():
            if self.public_contract() != expected:
                raise Refused('NEAR owner, network or role differs; no mutation authorized')
            return True
        artifacts = [
            '/etc/near/config.json', '/etc/systemd/system/near-node.service',
            '/etc/credstore.encrypted/near-node.key', '/etc/credstore.encrypted/near-validator.key',
            '/etc/erpc/near/identity.json', '/etc/erpc/near/installed.json',
            '/etc/erpc/near/installing.json', '/var/lib/near/data', '/var/lib/near/node_key.json',
            '/var/lib/near/validator_key.json', '/etc/near/genesis.json',
            '/etc/credstore.encrypted/near-node.pending', '/etc/erpc/near/retired',
            '/etc/erpc/near/stopped', '/etc/erpc/near/activation-revoked',
            '/etc/erpc/near/validator-identity.json', '/etc/erpc/near/validator-import.json',
        ]
        if (not initial or any(self.path(path).exists() for path in artifacts)
                or (self.directory.exists() and any(self.directory.iterdir()))
                or (self.path(HELPERS).exists() and any(self.path(HELPERS).iterdir()))):
            raise Refused('missing ownership over retained NEAR data or identity')
        return False

    def reserve(self, expected):
        if self.contract(expected, initial=True):
            if (self.directory / 'installed.json').exists() or (self.directory / 'installing.json').exists():
                raise Refused('existing installation must use deploy, not initialization')
            record = self.account_plan(expected)
            self.account_sync()
            return record
        self.account_observed(None)
        self.account_home(None, initial=True)
        self.directory_guard(self.directory, create=True, mode=0o700)
        self.write('contract.json', {'format': 2, 'contract': expected})
        record = self.account_plan(expected)
        self.account_sync()
        return record

    def public_contract(self):
        recorded = self.read('contract.json')
        if isinstance(recorded, dict) and set(recorded) == {'format', 'contract'} and type(recorded['format']) is int and recorded['format'] == 2:
            return self.expected(recorded['contract'])
        return self.expected(recorded)  # Legacy scope remains usable for owned shutdown.

    def account_protocol(self, expected):
        self.contract(expected)
        if self.read('contract.json') != {'format': 2, 'contract': expected}:
            raise Refused('legacy service account requires reviewed migration before startup or provisioning')

    def account_snapshot(self):
        return list(pwd.getpwall()), list(grp.getgrall())

    def account_lookup(self, kind, value):
        lookup = {'user_name': pwd.getpwnam, 'user_id': pwd.getpwuid,
                  'group_name': grp.getgrnam, 'group_id': grp.getgrgid}[kind]
        try: return lookup(value)
        except KeyError: return None

    def account_record(self, expected):
        self.account_protocol(expected)
        file = self.directory / 'accounts-intent.json'
        if not file.exists(): return None
        value = self.read('accounts-intent.json')
        if (not isinstance(value, dict) or set(value) != {'format', 'contract', 'name', 'uid', 'gid', 'home', 'shell'}
                or type(value['format']) is not int or value['format'] != 1 or value['contract'] != expected
                or value['name'] != 'near' or value['home'] != '/var/lib/near' or value['shell'] != '/usr/sbin/nologin'
                or type(value['uid']) is not int or type(value['gid']) is not int
                or not 20000 <= value['uid'] <= 60000 or value['gid'] != value['uid']):
            raise Refused('original NEAR service-account reservation is invalid')
        return value

    def account_observed(self, record):
        users, groups = self.account_snapshot()
        named = [entry for entry in users if entry.pw_name == 'near']
        named_groups = [entry for entry in groups if entry.gr_name == 'near']
        resolved_user = self.account_lookup('user_name', 'near')
        resolved_group = self.account_lookup('group_name', 'near')
        if record is None:
            if named or named_groups or resolved_user is not None or resolved_group is not None:
                raise Refused('unknown existing near account/group cannot be adopted')
            return None, None
        if (len(named) > 1 or len(named_groups) > 1
                or [entry for entry in users if entry.pw_uid == record['uid']] != named
                or [entry for entry in groups if entry.gr_gid == record['gid']] != named_groups):
            raise Refused('reserved NEAR UID/GID has another owner')
        user = named[0] if named else None
        group = named_groups[0] if named_groups else None
        def user_shape(value):
            return None if value is None else (value.pw_name, value.pw_uid, value.pw_gid, value.pw_dir, value.pw_shell)
        def group_shape(value):
            return None if value is None else (value.gr_name, value.gr_gid, frozenset(value.gr_mem))
        if (user_shape(resolved_user) != user_shape(user)
                or user_shape(self.account_lookup('user_id', record['uid'])) != user_shape(user)
                or group_shape(resolved_group) != group_shape(group)
                or group_shape(self.account_lookup('group_id', record['gid'])) != group_shape(group)):
            raise Refused('NEAR NSS name and numeric resolution disagree with enumeration')
        if group is not None and (group.gr_gid != record['gid'] or set(group.gr_mem) - {'near'}):
            raise Refused('original NEAR primary group is changed or shared')
        if any(entry.pw_gid == record['gid'] and entry.pw_name != 'near' for entry in users):
            raise Refused('another account shares the original NEAR primary group')
        if user is not None and (group is None or user.pw_uid != record['uid'] or user.pw_gid != record['gid']
                or user.pw_dir != record['home'] or user.pw_shell != record['shell']
                or set(os.getgrouplist('near', record['gid'])) != {record['gid']}):
            raise Refused('original NEAR UID/GID/home/shell or supplementary membership changed')
        return user, group

    def account_home(self, record, initial=False):
        self.directory_guard(self.home.parent)
        try: info = self.home.lstat()
        except FileNotFoundError:
            if initial: return
            raise Refused('original NEAR data home is missing') from None
        if not stat.S_ISDIR(info.st_mode): raise Refused('NEAR data home cannot be indirect')
        if record is not None and info.st_uid == record['uid'] and info.st_gid == record['gid'] and stat.S_IMODE(info.st_mode) == 0o700:
            return
        if initial and info.st_uid == ROOT_UID and not info.st_mode & 0o022 and not any(self.home.iterdir()):
            return  # Only an empty protected directory may receive reserved ownership.
        raise Refused('NEAR data home differs from original account authority')

    def account_plan(self, expected):
        record = self.account_record(expected)
        self.account_observed(record)
        if record is None:
            retained = ('accounts.json', 'accounts-reserved', 'identity.json', 'installed.json', 'installing.json')
            if any((self.directory / name).exists() for name in retained):
                raise Refused('missing original service-account reservation with retained state')
            self.account_home(None, initial=True)
            users, groups = self.account_snapshot()
            used = {entry.pw_uid for entry in users} | {entry.pw_gid for entry in users} | {entry.gr_gid for entry in groups}
            number = next((value for value in range(20000, 60001) if value not in used
                           and self.account_lookup('user_id', value) is None
                           and self.account_lookup('group_id', value) is None), None)
            if number is None: raise Refused('no unused dedicated NEAR UID/GID is available')
            record = {'format': 1, 'contract': expected, 'name': 'near', 'uid': number, 'gid': number,
                      'home': '/var/lib/near', 'shell': '/usr/sbin/nologin'}
            self.write('accounts-intent.json', record)
        self.account_home(record, initial=True)
        if (self.directory / 'accounts.json').exists():
            if self.read('accounts.json') != record or None in self.account_observed(record):
                raise Refused('established NEAR account receipt or NSS identity is missing')
        return record

    def account_sync(self):
        # Flush newly created namespace ancestry before NSS can outlive its receipt.
        path = self.directory
        while True:
            self.sync_directory(path)
            if path == self.root: break
            path = path.parent

    def accounts(self, expected):
        record = self.account_plan(expected)
        marker = {'reservation': self.digest(json.dumps(record, sort_keys=True, separators=(',', ':')).encode())}
        if (self.directory / 'accounts-reserved').exists():
            if self.read('accounts-reserved') != marker: raise Refused('account reservation marker differs')
        else:
            self.write('accounts-reserved', marker)  # Durable before any NSS operation.
        self.account_sync()
        user, group = self.account_observed(record)
        if group is None:
            self.command('/usr/sbin/groupadd', '--system', '--gid', str(record['gid']), 'near')
        user, group = self.account_observed(record)
        if user is None:
            self.command('/usr/sbin/useradd', '--system', '--uid', str(record['uid']), '--gid', str(record['gid']),
                         '--home-dir', record['home'], '--no-create-home', '--shell', record['shell'], '--groups', '', 'near')
        if None in self.account_observed(record): raise Refused('reserved NEAR account creation is incomplete')
        if not (self.directory / 'accounts.json').exists(): self.write('accounts.json', record)
        return {'uid': record['uid'], 'gid': record['gid']}

    def account(self, expected):
        record = self.account_record(expected)
        if record is None or self.read('accounts.json') != record or None in self.account_observed(record):
            raise Refused('original NEAR service-account authority is incomplete')
        marker = {'reservation': self.digest(json.dumps(record, sort_keys=True, separators=(',', ':')).encode())}
        if self.read('accounts-reserved') != marker: raise Refused('original NEAR account reservation marker is missing')
        self.account_home(record)
        return record['uid'], record['gid']


    def container(self, expected):
        result = self.docker('container', 'inspect', CONTAINER, check=False)
        if result.returncode:
            # Distinguish absence from a daemon/socket/permission error.
            listed = self.docker('container', 'ls', '--all', '--format', '{{.Names}}')
            if CONTAINER in listed.stdout.decode().splitlines():
                raise Refused('cannot establish container ownership')
            return None
        value = json.loads(result.stdout)
        if not isinstance(value, list) or len(value) != 1:
            raise Refused('ambiguous container identity')
        value = value[0]
        labels = value.get('Config', {}).get('Labels') or {}
        if labels.get('erpc.owner') != expected['owner'] or labels.get('erpc.network') != expected['network'] or labels.get('erpc.role') != expected['role']:
            raise Refused('container name belongs to another workload')
        return value

    def capacity(self, expected, usage=None):
        reserve = 100_000_000_000
        initial = 4_000_000_000_000 if expected['role'] == 'validator' else (3_500_000_000_000 if expected['network'] == 'mainnet' else 1_400_000_000_000)
        if usage is None:
            data = self.home / 'data'
            if data.is_symlink(): raise Refused('NEAR data directory cannot be indirect')
            if data.exists() and not data.is_dir(): raise Refused('NEAR data must be a directory')
            # A separately mounted data volume is authoritative. Allocation on
            # nested mounts must not subtract from this device's free budget.
            free = shutil.disk_usage(data if data.exists() else self.home).free
            output = self.command('du', '-s', '-x', '-B1', str(data), check=False)
            if data.exists() and output.returncode:
                raise Refused('could not measure the retained database')
            allocated = int(output.stdout.split()[0]) if data.exists() else 0
        else:
            free, allocated = usage
        if free < max(reserve, initial - min(initial - reserve, allocated)):
            raise Refused('insufficient free space for initial synchronization and operating headroom')

    def stopped(self, expected):
        self.contract(expected)
        self.container(expected)  # Refuse another workload before touching systemd.
        state = self.command('systemctl', 'show', '--property=LoadState', '--value', UNIT, check=False)
        loaded = state.stdout.decode().strip()
        if loaded != 'not-found':
            if state.returncode or loaded not in ('loaded', 'masked'):
                raise Refused('cannot establish the service state')
            self.command('systemctl', 'stop', UNIT)
        value = self.container(expected)
        if value and value.get('State', {}).get('Running'):
            identifier = value.get('Id', '')
            if not re.fullmatch('[a-f0-9]{64}', identifier): raise Refused('invalid owned container identity')
            self.docker('stop', '--time', '180', identifier)
            value = self.container(expected)
            if value and (value.get('Id') != identifier or value.get('State', {}).get('Running') is not False):
                raise Refused('owned container is still running or changed after shutdown')

    def target(self, expected, value, qualified=True):
        pin = PINS[expected['network']]
        if not isinstance(value, dict) or set(value) != {'version', 'commit', 'image', 'config_sha256', 'genesis_sha256', 'policy_sha256'}:
            raise Refused('invalid installation target')
        if qualified and any(value[key] != pin[key] for key in ('version', 'commit', 'image')):
            raise Refused('release is not qualified for this network')
        if not re.fullmatch(r'\d+\.\d+\.\d+(?:-rc\.\d+)?', value['version']) or not re.fullmatch('[a-f0-9]{40}', value['commit']):
            raise Refused('invalid installed release receipt')
        if not re.fullmatch('nearprotocol/nearcore@sha256:[a-f0-9]{64}', value['image']):
            raise Refused('invalid installed image receipt')
        for field in ('config_sha256', 'genesis_sha256', 'policy_sha256'):
            if not isinstance(value[field], str) or not re.fullmatch('[a-f0-9]{64}', value[field]):
                raise Refused('invalid installation digest')
        return value

    def file_digest(self, path):
        if not self.file_guard(path): raise Refused('protected artifact is missing')
        digest = hashlib.sha256()
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as file:
            self.file_info(os.fstat(file.fileno()))
            while block := file.read(1024 * 1024): digest.update(block)
            self.file_info(os.fstat(file.fileno()))
        return digest.hexdigest()

    def artifacts(self, target):
        for kind in ('config', 'genesis'):
            if self.file_digest(self.path('/etc/near/' + kind + '.json')) != target[kind + '_sha256']:
                raise Refused('protected network configuration changed')

    def upgrade_name(self, expected):
        return 'upgrade-' + PINS[expected['network']]['image'].rsplit(':',1)[1] + '.json'

    def forward_pending(self, expected, previous, target):
        self.target(expected, previous, qualified=False)
        self.target(expected, target)
        original=PREVIOUS_PINS.get(expected['network'])
        if original is None or any(previous[key]!=original[key] for key in original):
            raise Refused('pending release is not a qualified original forward-update source')
        if any(previous[key]!=target[key] for key in ('genesis_sha256','policy_sha256')):
            raise Refused('pending release update must retain its original genesis and access policy')

    def upgrade_record(self, expected):
        return self.validate_upgrade_record(expected,self.read(self.upgrade_name(expected)))

    def validate_upgrade_record(self, expected, value):
        if (not isinstance(value,dict) or set(value)!={'schema','contract','from','to','bootstrap'}
                or value['schema']!='near-pending-forward-v1' or value['contract']!=expected):
            raise Refused('original pending-update history differs')
        self.forward_pending(expected,value['from'],value['to'])
        bootstrap=value['bootstrap']
        wanted={'contract':expected,'image':value['from']['image'],'policy':value['from']['policy_sha256']}
        if (not isinstance(bootstrap,dict) or set(bootstrap)!={'request','peers'}
                or bootstrap['request']!=wanted or not isinstance(bootstrap['peers'],list)):
            raise Refused('original pending-update bootstrap differs')
        return value

    def fence_installation(self):
        # Older installed guards already recognize this pathname by presence.
        # Keep a restrictive file visible even if a later atomic JSON publication
        # fails before rename. Never truncate a previous cancellation marker.
        path=self.state_path('activation-revoked')
        self.file_guard(path,private=True)
        fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
        try:
            self.file_info(os.fstat(fd),private=True)
            os.fsync(fd)
        finally:os.close(fd)
        self.sync_directory(self.directory)

    def begin_install(self, expected, target, intent, allow_pending_upgrade=False):
        self.contract(expected)
        self.account(expected)
        self.target(expected, target)
        if not isinstance(intent, str) or not re.fullmatch('[a-f0-9]{32}', intent):
            raise Refused('deployment requires a unique caller intent')
        self.capacity(expected)
        pending = self.directory / 'installing.json'
        if type(allow_pending_upgrade) is not bool:
            raise Refused('invalid explicit forward-update choice')
        transition=None
        if pending.exists() and self.read('installing.json') != target:
            original=self.read('installing.json')
            self.forward_pending(expected,original,target)
            transition={'schema':'near-pending-forward-v1','contract':expected,'from':original,
                        'to':target,'bootstrap':self.read('bootstrap.json')}
            self.validate_upgrade_record(expected,transition)
            if self.state_path(self.upgrade_name(expected)).exists():
                if self.upgrade_record(expected)!=transition:
                    raise Refused('resume the original exact forward-update target')
            elif not allow_pending_upgrade:
                raise Refused('use explicit update to qualify this older pending release')
        if (self.directory / 'installed.json').exists():
            previous = self.read('installed.json')
            if previous['version'] == target['version'] and any(previous[key] != target[key] for key in ('commit', 'image')):
                raise Refused('changed executable source under an identical version requires a reviewed migration')
            if previous['version'] != target['version']:
                # Only reviewed CLI transitions can extend this rule; never auto-rollback a DB.
                def version(v):
                    found = re.fullmatch(r'(\d+)\.(\d+)\.(\d+)(?:-rc\.(\d+))?', v)
                    if not found: raise Refused('unrecognized installed version')
                    return tuple(int(x) for x in found.groups()[:3]) + (int(found[4]) if found[4] is not None else 2**31,)
                if version(target['version']) <= version(previous['version']):
                    raise Refused('database downgrade or ambiguous transition refused')
        # A separate durable revocation closes the gap even if publishing the
        # replacement intent fails while an identical old target is pending.
        try:
            self.fence_installation()
            self.write('activation-revoked', {'intent': intent})
            if transition is not None:
                name=self.upgrade_name(expected)
                if not self.state_path(name).exists():self.write(name,transition)
                if self.upgrade_record(expected)!=transition:
                    raise Refused('original pending-update history was not preserved')
            self.write('operation.json', {'intent': intent})
            self.write('installing.json', target)
        except Exception:
            try:self.stopped(expected)
            except Exception:
                raise Refused('installation persistence and original shutdown both failed; retain data and repair before retry') from None
            raise
        self.stopped(expected)
        # A crash between target publication and this receipt leaves the durable
        # original journal available to the next exact-target retry.
        bootstrap=self.directory/'bootstrap.json'
        if bootstrap.exists():
            saved=self.read('bootstrap.json')
            if saved.get('request',{}).get('image')!=target['image']:
                history=self.upgrade_record(expected)
                if history['to']!=target or saved!=history['bootstrap']:
                    raise Refused('pending-update bootstrap was changed')
                self.write('bootstrap.json',{'request':{'contract':expected,'image':target['image'],
                           'policy':target['policy_sha256']},'peers':saved['peers']})

    def finish_install(self, expected, target, intent):
        self.contract(expected)
        self.account(expected)
        self.target(expected, target)
        if self.read('installing.json') != target or self.read('operation.json') != {'intent': intent}:
            raise Refused('installation receipt differs')
        self.artifacts(target)
        self.identity(expected)
        self.write('installed.json', target)
        for name in ('retired', 'stopped', 'activation-revoked'):
            self.remove(name)
        # Keep the durable fence until a fresh SSH connection confirms this
        # exact policy and the final activation play consumes its receipt.

    def prepared(self, expected, policy, intent):
        self.contract(expected)
        self.account(expected)
        if any((self.directory / name).exists() for name in ('retired', 'stopped', 'activation-revoked')):
            raise Refused('queued activation was canceled or preparation is incomplete')
        if not isinstance(intent, str) or not re.fullmatch('[a-f0-9]{32}', intent) or self.read('operation.json') != {'intent': intent}:
            raise Refused('deployment was stopped or superseded by another caller')
        target = self.target(expected, self.read('installed.json'))
        if self.read('installing.json') != target or target['policy_sha256'] != policy:
            raise Refused('prepared node belongs to another configuration intent')
        self.artifacts(target)
        self.identity(expected)
        return target

    def firewall(self, receipt):
        if not isinstance(receipt, dict) or set(receipt) != {'run', 'bundle'}:
            raise Refused('invalid firewall receipt')
        if not re.fullmatch('[a-z0-9-]{1,80}', receipt['run']) or not re.fullmatch('[a-f0-9]{64}', receipt['bundle']):
            raise Refused('invalid firewall token')
        self.firewall_action('require-confirmed', receipt['run'], receipt['bundle'])

    def firewall_action(self, action, run=None, bundle=None):
        # The checked chain entrypoint protects the stdlib-only common helper;
        # sibling chains may legitimately use a closed current symlink.
        import runpy
        self.contract(self.public_contract())
        path = self.path('/usr/local/lib/erpc/rpc-firewall.py')
        if not self.file_guard(path): raise Refused('missing common firewall helper')
        helper = runpy.run_path(str(path), run_name='erpc_near_firewall')
        return helper['Firewall']('near').dispatch(action, run, bundle)

    def activate(self, expected, value):
        if not isinstance(value, dict) or set(value) != {'policy_sha256', 'firewall', 'intent'}:
            raise Refused('invalid activation request')
        self.prepared(expected, value['policy_sha256'], value['intent'])
        self.firewall(value['firewall'])
        self.write('firewall.json', value['firewall'])
        self.remove('installing.json')
        self.guard(expected)
        self.command('systemctl', 'enable', UNIT)
        self.command('systemctl', 'start', UNIT)

    def identity(self, expected):
        self.contract(expected)
        receipt = self.read('identity.json')
        encrypted = self.path('/etc/credstore.encrypted/near-node.key')
        if receipt['contract'] != expected or receipt['cipher_sha256'] != self.file_digest(encrypted):
            raise Refused('NEAR peer identity is missing or changed; explicit recovery required')
        return receipt

    def guard(self, expected, manual=False):
        self.contract(expected)
        self.account(expected)
        markers = ('retired', 'installing.json', 'activation-revoked') + (() if manual else ('stopped',))
        if any((self.directory / name).exists() for name in markers):
            raise Refused('service is fenced by retirement or incomplete installation')
        installed = self.read('installed.json')
        self.target(expected, installed)
        self.artifacts(installed)
        self.identity(expected)
        self.capacity(expected)
        self.firewall(self.read('firewall.json'))
        if expected['role'] == 'validator':
            import near_validator
            near_validator.identity(self, expected)
            self.clock()
            near_validator.observe(expected, block_age)
        return installed

    def clock(self):
        value = self.command('timedatectl', 'show', '--property=NTPSynchronized', '--value').stdout.decode().strip()
        if value != 'yes': raise Refused('validator requires a synchronized host clock')

    def cancel(self, expected, retired=False):
        self.contract(expected)
        persisted = True
        # Attempt both independent fences. Failure of either remains an error,
        # but must not prevent best-effort shutdown of the owned workload.
        for name, value in [('retired' if retired else 'stopped', {'contract': expected}),
                            ('operation.json', {'intent': None})]:
            try:
                self.write(name, value)
            except Exception:
                persisted = False
        try:
            self.stopped(expected)
            if retired:
                state = self.command('systemctl', 'show', '--property=LoadState', '--value', UNIT, check=False)
                loaded = state.stdout.decode().strip()
                if loaded != 'not-found':
                    if state.returncode or loaded not in ('loaded', 'masked'):
                        raise Refused('cannot establish the service state before retirement disable')
                    self.command('systemctl', 'disable', UNIT)
        except Exception:
            if not persisted:
                raise Refused('NEAR cancellation could not be persisted and owned shutdown also failed') from None
            raise
        if not persisted:
            raise Refused('NEAR owned shutdown attempted but cancellation was not persisted; repair storage before relying on restart protection')

    def service(self, expected, action, value=None):
        self.contract(expected)
        if action == 'stop':
            self.cancel(expected)
            return
        installed = self.guard(expected, manual=True)
        if not isinstance(value, dict) or value != {'policy_sha256': installed['policy_sha256']}:
            raise Refused('desired configuration differs; resume deployment before startup')
        self.container(expected)
        if action not in ('start', 'restart'): raise Refused('unsupported service operation')
        self.remove('stopped')
        self.command('systemctl', action, UNIT)

    def status(self, expected):
        self.contract(expected)
        installed = self.read('installed.json') if (self.directory / 'installed.json').exists() else None
        result = {'network': expected['network'], 'role': expected['role'], 'ready': False,
                  'installed': installed, 'phase': 'prepared' if installed is None else 'installed'}
        if expected['role'] == 'validator': result['producer_eligible'] = False
        for marker, phase in [('activation-revoked', 'installing'), ('installing.json', 'installing'), ('stopped', 'stopped'), ('retired', 'retired')]:
            if (self.directory / marker).exists(): result['phase'] = phase
        result['service'] = self.command('systemctl', 'is-active', UNIT, check=False).stdout.decode().strip()
        try:
            self.firewall(self.read('firewall.json'))
            result['firewall_confirmed'] = True
        except (Refused, OSError, KeyError, ValueError):
            result['firewall_confirmed'] = False
        try:
            uid, gid = self.account(expected)
            container = self.container(expected)
            if not container or container.get('State', {}).get('Running') is not True:
                raise Refused('owned node is not running')
            if container.get('Config', {}).get('User') != str(uid) + ':' + str(gid):
                raise Refused('running container differs from original runtime UID/GID')
            pid = container['State']['Pid']
            if type(pid) is not int or pid <= 0: raise Refused('invalid owned process')
            sockets = self.command('ss', '-H', '-lntp').stdout.decode().splitlines()
            listeners = [line for line in sockets if len(line.split()) >= 5 and line.split()[3] in ('127.0.0.1:3030', '0.0.0.0:3030')]
            if len(listeners) != 1 or not re.search(r'pid=' + str(pid) + r'(?:,|\))', listeners[0]):
                raise Refused('RPC listener is not owned by this container')
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *_args, **_kwargs): raise Refused('local status cannot redirect')
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
            with opener.open('http://127.0.0.1:3030/status', timeout=10) as response:
                raw = response.read(1048577)
            if len(raw) > 1048576: raise Refused('oversized node status')
            value = json.loads(raw)
            if value['chain_id'] != expected['network'] or value['genesis_hash'] != expected['genesis_hash']:
                raise Refused('status network identity differs')
            if expected['role'] == 'validator':
                if value.get('validator_account_id') != expected['validator_account'] or value.get('validator_public_key') != expected['staking_public_key']:
                    raise Refused('native validator account or public key differs')
                import near_validator
                near_validator.identity(self, expected)
                self.clock()
                result['registration'] = near_validator.observe(expected, block_age)
            elif value.get('validator_account_id') is not None or value.get('validator_public_key') is not None:
                raise Refused('RPC follower unexpectedly has a validator identity')
            if value['node_public_key'] != self.identity(expected)['public_key']:
                raise Refused('RPC peer identity differs')
            if not installed or value['version']['version'] != installed['version'] or value['version']['commit'] != installed['commit']:
                raise Refused('running binary version/source differs from the installed receipt')
            sync = value['sync_info']
            age = block_age(sync['latest_block_time'])
            result.update(syncing=sync['syncing'], height=sync['latest_block_height'], block_age_seconds=age,
                          version=value['version'], protocol_version=value['protocol_version'])
            result['ready'] = (result['phase'] == 'installed' and result['service'] == 'active'
                               and result['firewall_confirmed'] and sync['syncing'] is False and -120 <= age <= 300)
            if expected['role'] == 'validator':
                observed = result['registration']
                result['producer_eligible'] = result['ready'] and observed['pool_exists'] and not observed['staking_paused'] and observed['current_validators']
        except (Refused, OSError, ValueError, KeyError, TypeError):
            result['inspection_error'] = 'owned node identity or readiness was not established'
        return result

    def retire(self, expected):
        self.cancel(expected, retired=True)

    def stop_container(self, expected):
        self.contract(expected)
        value = self.container(expected)
        if value and value.get('State', {}).get('Running'):
            identifier = value.get('Id', '')
            if not re.fullmatch('[a-f0-9]{64}', identifier): raise Refused('invalid container identity')
            self.docker('stop', '--time', '180', identifier)

    def stage_runtime_key(self, expected):
        uid, gid = self.account(expected)
        receipt = self.identity(expected)
        source = self.path('/run/credentials/near-node.service/node-key.json')
        info = source.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > 4096:
            raise Refused('invalid decrypted credential')
        raw = source.read_bytes()
        key = json.loads(raw)
        if set(key) != {'account_id', 'public_key', 'secret_key'} or key['public_key'] != receipt['public_key']:
            raise Refused('decrypted peer identity does not match its receipt')
        if self.digest(raw) != receipt['plaintext_sha256']:
            raise Refused('decrypted peer credential changed')
        directory = self.path('/run/erpc-near/keys')
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if directory.is_symlink(): raise Refused('runtime credential directory is indirect')
        os.chown(directory, 0, gid)
        os.chmod(directory, 0o750)
        materials = [('node_key.json', raw)]
        if expected['role'] == 'validator':
            import near_validator
            validator_receipt = near_validator.identity(self, expected)
            source = self.path('/run/credentials/near-node.service/validator-key.json')
            info = source.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_size > 4096: raise Refused('invalid validator runtime credential')
            validator_raw = source.read_bytes()
            if self.digest(validator_raw) != validator_receipt['plaintext_sha256']:
                raise Refused('runtime consensus credential differs from the original')
            near_validator.key_material(self, expected, validator_raw)
            materials.append(('validator_key.json', validator_raw))
        elif (directory / 'validator_key.json').exists():
            raise Refused('RPC runtime unexpectedly contains validator material')
        for name, material in materials:
            fd, temporary = tempfile.mkstemp(prefix='.key-', dir=directory)
            try:
                with os.fdopen(fd, 'wb') as output:
                    output.write(material)
                os.chown(temporary, 0, gid)
                os.chmod(temporary, 0o440)
                os.replace(temporary, directory / name)
            finally:
                Path(temporary).unlink(missing_ok=True)
        return uid, gid

    def launch(self, expected):
        installed = self.guard(expected)
        # No daemon wallet, no inherited Docker endpoint/config and no image entry script.
        previous = self.container(expected)
        if previous:
            identifier = previous.get('Id', '')
            if not re.fullmatch('[a-f0-9]{64}', identifier): raise Refused('invalid container identity')
            if previous.get('State', {}).get('Running'):
                raise Refused('owned container is already running outside its service')
            self.docker('container', 'rm', identifier)
        uid, gid = self.stage_runtime_key(expected)
        argv = ['docker', '--host', 'unix:///var/run/docker.sock', '--config', '/etc/erpc/near/docker',
                'run', '--rm', '--name', CONTAINER, '--network', 'host', '--read-only',
                '--user', str(uid) + ':' + str(gid), '--cap-drop', 'ALL',
                '--security-opt', 'no-new-privileges=true', '--pids-limit', '8192',
                '--ulimit', 'core=0:0', '--ulimit', 'nofile=1048576:1048576',
                '--label', 'erpc.owner=' + expected['owner'],
                '--label', 'erpc.network=' + expected['network'], '--label', 'erpc.role=' + expected['role'],
                '--mount', 'type=bind,src=/var/lib/near,dst=/var/lib/near',
                '--mount', 'type=bind,src=/etc/near/config.json,dst=/var/lib/near/config.json,readonly',
                '--mount', 'type=bind,src=/etc/near/genesis.json,dst=/etc/near/genesis.json,readonly',
                '--mount', 'type=bind,src=/run/erpc-near/keys,dst=/run/near-keys,readonly',
                '--tmpfs', '/tmp:rw,nosuid,nodev,size=256m',
                '--entrypoint', '/usr/local/bin/neard', installed['image'], '--home', '/var/lib/near', 'run']
        # The systemd unit owns this attached process. No shell or sensitive environment survives.
        os.execvpe('/usr/bin/docker', argv, {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'})

    def dispatch(self, action, expected, value=None, locked=False):
        self.expected(expected)
        if action == 'guard-init': return self.contract(expected, initial=True)
        if action == 'contract': return self.contract(expected)
        if action == 'account': return self.account(expected)
        if action == 'publication': return self.publication(expected)
        if action == 'firewall-publication': return self.publication(expected, firewall=True)
        if action == 'run': return self.launch(expected)
        if action == 'stop-container': return self.stop_container(expected)
        if action == 'guard': return self.guard(expected)  # Read-only systemd precondition.
        if action == 'status': return self.status(expected)
        if action in ('registration', 'validate-registration'):
            self.contract(expected)
            if expected['role'] != 'validator': raise Refused('validator operation requires validator role')
            import near_validator
            if action == 'validate-registration': near_validator.identity(self, expected)
            return near_validator.observe(expected, block_age, balances=True)
        if action == 'prepared': return self.prepared(expected, value['policy_sha256'], value['intent'])
        fd = None
        if not locked:
            fd = os.open(self.path('/opt/erpc'), os.O_RDONLY)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except Exception:
                os.close(fd)
                raise
        try:
            if action == 'reserve': return self.reserve(expected)
            if action == 'accounts': return self.accounts(expected)
            if action == 'activate': return self.activate(expected, value)
            if action in ('start', 'stop', 'restart'): return self.service(expected, action, value)
            if action == 'retire': return self.retire(expected)
            if action == 'import-validator':
                import near_validator
                return near_validator.import_key(self, expected, value, block_age)
            raise Refused('unsupported NEAR operation')
        finally:
            if fd is not None: os.close(fd)


def main():
    import base64
    import resource
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    trusted_imports(os.path.dirname(os.path.abspath(__file__)))
    if len(sys.argv) >= 2 and sys.argv[1] in ('firewall-confirm', 'firewall-load'):
        if sys.argv[1] == 'firewall-load' and len(sys.argv) == 2:
            return Control().firewall_action('load')
        if sys.argv[1] == 'firewall-confirm' and len(sys.argv) == 4:
            return Control().firewall_action('confirm', sys.argv[2], sys.argv[3])
        raise Refused('invalid firewall operation')
    if len(sys.argv) != 3: raise Refused('expected operation and public contract')
    expected = json.loads(base64.b64decode(sys.argv[2], validate=True))
    data = sys.stdin.buffer.read(65537)
    if len(data) > 65536: raise Refused('oversized operation input')
    value = json.loads(data) if data else None
    action = sys.argv[1]
    locked = action.startswith('play-')
    if locked:
        action = action[5:]
        if action not in ('reserve', 'accounts', 'activate', 'retire'):
            raise Refused('invalid play-owned operation')
    result = Control().dispatch(action, expected, value, locked=locked)
    if result is not None: print(json.dumps(result))


if __name__ == '__main__':
    try:
        main()
    except Refused as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
    except Exception:
        # The controller now accepts original consensus material on stdin;
        # malformed responses or key input must never produce a traceback.
        print('NEAR operation refused; ownership, identity or deployment prerequisites were not verified', file=sys.stderr)
        raise SystemExit(1)
