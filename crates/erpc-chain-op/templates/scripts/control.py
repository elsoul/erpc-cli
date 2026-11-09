#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Owned follower operations. Provider credentials are accepted only on stdin."""
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


import fcntl
import base64
import hashlib
import ipaddress
import json
import os
import pwd
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import time
import http.client
from urllib.parse import urlsplit

OWNER = Path('/etc/erpc/rollup-owner.json')
LOCK = Path('/opt/erpc')
LIB = Path('/usr/local/lib/erpc')
CREDENTIALS = Path('/etc/credstore.encrypted')
FAMILIES = {'optimism': {'mainnet', 'sepolia'}, 'base': {'mainnet', 'sepolia'}, 'soneium': {'mainnet', 'minato'}}
OWNER_UID = 0
PROC = Path('/proc')
CGROUP = Path('/sys/fs/cgroup')
IDENTITY_NAMES = ('engine-jwt', 'execution-peer', 'consensus-peer')
SECP256K1_ORDER = 2 ** 256 - 432420386565659656852420866394968145599
PHASES = {'prepared', 'installing', 'bootstrapping', 'installed', 'retired', 'resetting'}


class Refused(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Refused(message)


def run(args, *, data=None, timeout=120, allowed=(0,)):
    result = subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout, check=False,
                            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    require(result.returncode in allowed, 'owned follower operation failed; inspect its journal')
    return result.stdout


def root_file(path):
    require(path.is_file() and not path.is_symlink(), 'owned file missing or unsafe')
    info = path.stat()
    require(info.st_uid == OWNER_UID and info.st_mode & 0o022 == 0, 'owned file must be root-owned and not writable by others')


def atomic(path, data, mode=0o600):
    require(not path.is_symlink(), 'unsafe output path')
    temporary = path.with_name(path.name + '.new')
    require(not temporary.is_symlink(), 'unsafe output temporary path')
    temporary.unlink(missing_ok=True)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_state(state):
    atomic(OWNER, json.dumps(state, sort_keys=True).encode())


def validate_contract(value, allow_unassigned=False):
    require(isinstance(value, dict) and set(value) == {'owner', 'family', 'network', 'history'}, 'invalid follower ownership format')
    require(value['family'] in FAMILIES and value['network'] in FAMILIES[value['family']], 'unsupported follower network')
    require(value['history'] in {'full', 'archive'}, 'unsupported follower history policy')
    owner = value['owner']
    require(isinstance(owner, str) and ((allow_unassigned and owner == '') or re.fullmatch(r'[a-zA-Z0-9]{1,80}', owner)), 'invalid follower inventory owner')


def read_state():
    root_file(OWNER)
    state = json.loads(OWNER.read_bytes())
    require(type(state.get('format')) is int and state['format'] == 1 and state.get('phase') in PHASES
            and type(state.get('bootstrap_done')) is bool and type(state.get('upstreams_installed', False)) is bool, 'unsupported follower state')
    validate_contract(state['contract'])
    return state


def paths(contract):
    family = contract['family']
    return Path('/etc/erpc') / family, Path('/var/lib/erpc') / family, Path('/opt/erpc') / family


def units(contract):
    return {name: 'erpc-' + contract['family'] + '-' + name for name in
            ('consensus', 'execution', 'upstreams', 'rpc', 'bootstrap', 'firewall')}


def service_active(name):
    result = run(['systemctl', 'is-active', name], allowed=(0, 3, 4)).decode().strip()
    require(result in {'active', 'activating', 'deactivating', 'inactive', 'failed', 'unknown'}, 'cannot determine follower process state')
    return result


def native_quiescent(contract, groups):
    """A missing/inactive systemd unit does not prove a native writer stopped."""
    if contract['family'] != 'base':
        return
    identities = set()
    for name in ('erpc-base', 'erpc-base-l1'):
        try:
            account = pwd.getpwnam(name)
        except KeyError as error:
            raise Refused('cannot establish native follower process ownership') from error
        require(account.pw_uid > 0, 'native follower account must be unprivileged')
        identities.add(account.pw_uid)
    for group in groups:
        require(group.startswith('/') and '..' not in group.split('/'), 'unsafe native service cgroup')
        directory = CGROUP / group.lstrip('/')
        require(not directory.is_symlink(), 'unsafe native service cgroup')
        if directory.exists():
            for file in directory.rglob('cgroup.procs'):
                require(not file.is_symlink() and not file.read_text().strip(), 'native service cgroup still has processes')
    processes = [path for path in PROC.iterdir() if path.name.isdecimal()]
    require(processes, 'native process table could not be inspected')
    for process in processes:
        try:
            status = (process / 'status').read_text()
        except FileNotFoundError:
            require(not process.exists(), 'native process ownership became unreadable')
            continue  # The process exited during enumeration.
        try:
            executable = os.readlink(process / 'exe').removesuffix(' (deleted)')
        except FileNotFoundError:
            executable = ''  # Kernel thread or a process that exited during inspection.
        require(Path(executable).name not in {'base-reth-node', 'base-consensus'},
                'a native Base client survives outside its stopped unit; explicit recovery required')
        try:
            arguments = (process / 'cmdline').read_bytes().split(b'\0')
        except FileNotFoundError:
            arguments = []
        require(str(LIB / 'rollup_bootstrap.py').encode() not in arguments,
                'a native bootstrap worker survives its stopped unit; explicit recovery required')
        rows = [line.split()[1:] for line in status.splitlines() if line.startswith('Uid:')]
        require(len(rows) == 1 and len(rows[0]) == 4 and all(x.isdecimal() for x in rows[0]),
                'native process credentials could not be inspected')
        require(identities.isdisjoint(int(x) for x in rows[0]),
                'a native follower process survives outside its stopped unit; explicit recovery required')


def stop(contract):
    names = units(contract)
    groups = []
    for name in ('bootstrap', 'rpc', 'consensus', 'execution', 'upstreams'):
        unit = names[name]
        loaded = run(['systemctl', 'show', '-p', 'LoadState', '--value', unit], allowed=(0, 1)).strip()
        if loaded == b'not-found':
            continue
        require(loaded in {b'loaded', b'masked'}, 'cannot determine owned service state')
        if contract['family'] == 'base':
            group = run(['systemctl', 'show', '-p', 'ControlGroup', '--value', unit]).decode().strip()
            if group:
                groups.append(group)
        run(['systemctl', 'stop', unit], timeout=660)
        require(service_active(unit) in {'inactive', 'failed', 'unknown'}, 'owned service did not stop')
        require(run(['systemctl', 'show', '-p', 'MainPID', '--value', unit]).strip() in {b'0', b''}, 'owned process is still running')

    native_quiescent(contract, groups)
    state = read_state()
    check(state, contract)
    if contract['family'] != 'base' and state.get('pair'):
        trusted_imports(LIB)
        import rollup_container
        for role in ('consensus', 'execution'):
            rollup_container.stop_owned(state, role)


def check(state, contract):
    validate_contract(contract)
    require(state['contract'] == contract, 'follower owner/chain/network/history mismatch; nothing changed')
    conf, data, opt = paths(contract)
    for path in (OWNER.parent, conf, data, opt):
        require(not path.is_symlink(), 'unsafe follower directory')


def capacity(state):
    _, data, _ = paths(state['contract'])
    probe = data
    while not probe.exists():
        probe = probe.parent
    free = shutil.disk_usage(probe).free
    # Import completion is not chain synchronization: a genesis bootstrap marks
    # done before the EL downloads its database. Keep the allocation-derived
    # provisioning floor on every start/resume; never trust a completion marker
    # to waive initial-sync space. The operating reserve is independent.
    required = state.get('bootstrap', {}).get('required_free_bytes')
    require(type(required) is int and 200_000_000_000 <= required <= 100_000_000_000_000,
            'missing or invalid initial-sync capacity requirement')
    allocated = 0
    for name in ('execution', 'bootstrap-cache'):
        path = data / name
        require(not path.is_symlink(), 'unsafe bootstrap data directory')
        if path.exists():
            require(path.is_dir() and path.stat().st_dev == probe.stat().st_dev, 'bootstrap data must share its provisioned filesystem')
            raw = run(['du', '-sx', '-B1', str(path)]).split()
            require(raw and raw[0].isdigit(), 'cannot measure bootstrap allocation')
            allocated += int(raw[0])
    required = max(200_000_000_000, required - allocated)
    require(free >= required, 'insufficient initial-sync space or operational headroom')


def preflight(contract):
    validate_contract(contract, allow_unassigned=True)
    if OWNER.exists() or OWNER.is_symlink():
        state = read_state()
        if not contract['owner']:
            require(False, 'host already has a follower owner; use its existing inventory')
        check(state, contract)
        return {'phase': state['phase'], 'owned': True}
    for family in FAMILIES:
        for unit in units({'family': family}).values():
            loaded = run(['systemctl', 'show', '-p', 'LoadState', '--value', unit], allowed=(0, 1)).strip()
            require(loaded == b'not-found', 'unowned follower service exists')
        for account in ('erpc-' + family, 'erpc-' + family + '-l1'):
            try:
                pwd.getpwnam(account)
            except KeyError:
                pass
            else:
                raise Refused('an unowned follower service account exists')
        for path in paths({'family': family}):
            require(not path.exists() and not path.is_symlink(), 'unowned follower state exists; explicit recovery required')
    listeners = run(['ss', '-Hlnut']).decode().splitlines()
    reserved = {8545, 8546, 8551, 8555, 8556, 9060, 9545, 6060, 7300, 18545, 15052, 30303, 9200, 9222, 9223}
    for line in listeners:
        fields = line.split()
        require(len(fields) >= 5, 'cannot inspect host listener ownership')
        port = fields[4].rsplit(':', 1)[-1]
        require(not port.isdecimal() or int(port) not in reserved, 'an unowned service occupies a follower port')
    return {'phase': 'unowned', 'owned': False}


def validate_bootstrap(contract, pin):
    fields = {'kind', 'url', 'sha256', 'required_free_bytes', 'chain_id'}
    cids = {'optimism': {'mainnet': 10, 'sepolia': 11155420},
            'base': {'mainnet': 8453, 'sepolia': 84532}, 'soneium': {'mainnet': 1868, 'minato': 1946}}
    require(isinstance(pin, dict) and set(pin) == fields and pin['chain_id'] == cids[contract['family']][contract['network']], 'bootstrap ownership mismatch')
    require(type(pin['required_free_bytes']) is int and 200_000_000_000 <= pin['required_free_bytes'] <= 100_000_000_000_000, 'invalid bootstrap capacity')
    if pin['kind'] == 'genesis':
        require(contract['family'] != 'base' and not (contract['family'] == 'optimism' and contract['network'] == 'mainnet')
                and pin['url'] == '' and pin['sha256'] == '', 'wrong genesis bootstrap network')
        return
    require(isinstance(pin['url'], str) and re.fullmatch('[a-f0-9]{64}', pin['sha256']), 'invalid bootstrap metadata pin')
    url = urlsplit(pin['url'])
    require(url.scheme == 'https' and url.username is None and url.password is None and url.port is None
            and not url.query and not url.fragment, 'unsafe bootstrap source')
    if pin['kind'] == 'base-manifest':
        host = ('mainnet' if contract['network'] == 'mainnet' else 'sepolia') + '-v2-snapshots.base.org'
        require(contract['family'] == 'base' and url.hostname == host
                and re.fullmatch('/[0-9]+/manifest.json', url.path), 'wrong Base snapshot source')
    elif pin['kind'] == 'op-archive':
        require(contract['family'] == 'optimism' and contract['network'] == 'mainnet' and url.hostname == 'datadirs.optimism.io'
                and re.fullmatch('/mainnet-op-mainnet-reth-' + contract['history'] + '-storage-v2-[0-9]{4}-[0-9]{2}-[0-9]{2}\.tar\.zst', url.path), 'wrong OP snapshot source')
    else:
        raise Refused('unsupported bootstrap source')


def prepare(request):
    contract = request['contract']
    validate_contract(contract)
    validate_bootstrap(contract, request['bootstrap'])
    result = preflight(contract)
    if result['owned']:
        return result
    state = {'format': 1, 'contract': contract, 'phase': 'prepared', 'bootstrap_done': False,
             'bootstrap': request['bootstrap']}
    capacity(state)
    OWNER.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    write_state(state)
    return {'phase': 'prepared', 'owned': True}


def credential_name(contract, name):
    return 'erpc-' + contract['family'] + '-' + name


def encrypt(contract, name, value):
    CREDENTIALS.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(not CREDENTIALS.is_symlink() and CREDENTIALS.stat().st_uid == OWNER_UID, 'unsafe credential store')
    label = credential_name(contract, name)
    # systemd encrypt writes only encrypted output to disk. Its stderr may echo
    # diagnostics, so run() never relays it to callers or the journal.
    encrypted = run(['systemd-creds', 'encrypt', '--name=' + name, '-', '-'], data=value)
    require(encrypted and len(encrypted) <= 131072, 'invalid encrypted credential output')
    atomic(CREDENTIALS / label, encrypted)


def identity_material(name):
    while True:
        value = secrets.token_bytes(32)
        if name == 'engine-jwt' or 0 < int.from_bytes(value, 'big') < SECP256K1_ORDER:
            return value.hex().encode()


def identity_receipt(state):
    receipt = state.get('identity')
    require(isinstance(receipt, dict) and set(receipt) == set(IDENTITY_NAMES),
            'original follower identity receipt is missing; explicit recovery required')
    result = {}
    for name, item in receipt.items():
        require(isinstance(item, dict) and set(item) == {'encrypted', 'plaintext_sha256', 'cipher_sha256'},
                'invalid follower identity receipt')
        require(all(isinstance(item[k], str) and re.fullmatch('[a-f0-9]{64}', item[k])
                    for k in ('plaintext_sha256', 'cipher_sha256')), 'invalid follower identity hashes')
        require(isinstance(item['encrypted'], str) and len(item['encrypted']) <= 180000, 'invalid retained encrypted identity')
        encrypted = base64.b64decode(item['encrypted'], validate=True)
        require(encrypted and len(encrypted) <= 131072
                and hashlib.sha256(encrypted).hexdigest() == item['cipher_sha256'], 'retained encrypted identity changed')
        result[name] = encrypted
    return result


def verify_identity(state):
    for name, expected in identity_receipt(state).items():
        file = CREDENTIALS / credential_name(state['contract'], name)
        root_file(file)
        require(file.read_bytes() == expected, 'original follower credential missing, corrupted or substituted; explicit recovery required')


def initialize_identity(state):
    if state.get('pair'):
        verify_identity(state)
        return
    CREDENTIALS.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(not CREDENTIALS.is_symlink() and CREDENTIALS.stat().st_uid == OWNER_UID, 'unsafe credential store')
    if 'identity' not in state:
        for name in IDENTITY_NAMES:
            file = CREDENTIALS / credential_name(state['contract'], name)
            require(not file.exists() and not file.is_symlink(), 'unreceipted identity material requires explicit recovery')
        receipt = {}
        for name in IDENTITY_NAMES:
            value = identity_material(name)
            encrypted = run(['systemd-creds', 'encrypt', '--name=' + name, '-', '-'], data=value)
            require(encrypted and len(encrypted) <= 131072, 'invalid encrypted initial identity')
            receipt[name] = {'encrypted': base64.b64encode(encrypted).decode(),
                             'plaintext_sha256': hashlib.sha256(value).hexdigest(),
                             'cipher_sha256': hashlib.sha256(encrypted).hexdigest()}
        # The atomic private owner record contains only encrypted material. It is
        # authoritative before any individual credential is published. Interrupted
        # first publication reuses these exact bytes, never fresh entropy.
        state['identity'] = receipt
        write_state(state)
    for name, encrypted in identity_receipt(state).items():
        file = CREDENTIALS / credential_name(state['contract'], name)
        if file.exists() or file.is_symlink():
            root_file(file)
            require(file.read_bytes() == encrypted, 'initial identity publication differs from its receipt')
        else:
            atomic(file, encrypted)
    verify_identity(state)


def runtime_identity(state, name):
    require(name in IDENTITY_NAMES, 'unknown runtime identity')
    directory = os.environ.get('CREDENTIALS_DIRECTORY')
    require(directory, 'systemd runtime credentials are unavailable')
    path = Path(directory) / name
    require(path.is_file() and not path.is_symlink() and path.stat().st_size == 64, 'invalid runtime credential file')
    value = path.read_bytes()
    require(re.fullmatch(b'[a-f0-9]{64}', value), 'invalid runtime credential format')
    require(name == 'engine-jwt' or 0 < int(value, 16) < SECP256K1_ORDER, 'invalid runtime peer identity')
    require(hashlib.sha256(value).hexdigest() == state['identity'][name]['plaintext_sha256'],
            'decrypted identity does not match its original receipt')
    return value


def cancel_deployment(state):
    generation = state.get('lifecycle_generation', 0)
    require(type(generation) is int and 0 <= generation < 2 ** 63, 'invalid lifecycle generation')
    state['lifecycle_generation'] = generation + 1
    state['deploy_intent'] = None


def require_deploy(state, request):
    intent = request.get('intent')
    require(isinstance(intent, str) and re.fullmatch(r'r-[a-z0-9-]{8,40}', intent)
            and state.get('deploy_intent') == intent, 'deployment was stopped or superseded; start a fresh operation')


def authorize_deploy(state, request):
    intent = request.get('intent')
    require(isinstance(intent, str) and re.fullmatch(r'r-[a-z0-9-]{8,40}', intent), 'invalid deployment intent')
    require(state['phase'] not in {'bootstrapping', 'resetting'}, 'resume existing bootstrap or recovery first')
    if state['phase'] == 'installing':
        require(state['target'] == request['pair'], 'resume the exact interrupted installation target')
    if state.get('pair'):
        verify_identity(state)
    state['deploy_intent'] = intent
    write_state(state)
    return {'deployment_authorized': True}


def configure_upstreams(state, request):
    require_deploy(state, request)
    if state.get('pair'):
        verify_identity(state)
    require(state['phase'] != 'bootstrapping' or service_active(units(state['contract'])['bootstrap']) in {'inactive', 'failed'}, 'stop bootstrap before rotating upstreams')
    receipt = request['firewall']
    run(['/usr/bin/python3', '-I', str(LIB / 'rpc-firewall.py'), state['contract']['family'], 'require-confirmed', receipt['run'], receipt['bundle']])
    # Import only the carried validator. Credentials are never returned from it.
    trusted_imports(LIB)
    import rollup_upstreams
    config = request['upstreams']
    l1 = 'mainnet' if state['contract']['network'] == 'mainnet' else 'sepolia'
    rollup_upstreams.Upstreams(config, l1)
    encoded = json.dumps(config, separators=(',', ':'), allow_nan=False).encode()
    require(len(encoded) <= 65536, 'upstream credential exceeds limit')
    encrypt(state['contract'], 'l1-upstreams', encoded)
    state['upstreams_installed'] = True
    write_state(state)
    return {'credential_installed': True}


def verify_files(state):
    conf, _, _ = paths(state['contract'])
    root_file(conf / 'installation.json')
    manifest = json.loads((conf / 'installation.json').read_bytes())
    require(manifest.get('contract') == state['contract'] and manifest.get('pair') == state.get('target', state.get('pair')),
            'installation does not match requested clients and ownership')
    require(isinstance(manifest.get('files'), dict) and manifest['files'], 'installation has no protected files')
    for name, digest in manifest['files'].items():
        path = Path(name)
        allowed = (path.is_relative_to(conf) or path.is_relative_to(LIB)
                   or path.parent == Path('/etc/systemd/system'))
        require(allowed and re.fullmatch('[a-f0-9]{64}', digest), 'invalid installation file receipt')
        root_file(path)
        require(hashlib.sha256(path.read_bytes()).hexdigest() == digest, 'protected follower configuration changed')
    return manifest


def firewall(state, command='guard'):
    family = state['contract']['family']
    run(['/usr/bin/python3', '-I', str(LIB / 'rpc-firewall.py'), family, command])


def validate_accounts(contract):
    node = pwd.getpwnam('erpc-' + contract['family'])
    proxy = pwd.getpwnam('erpc-' + contract['family'] + '-l1')
    require(node.pw_uid > 0 and proxy.pw_uid > 0 and node.pw_uid != proxy.pw_uid
            and node.pw_gid > 0 and proxy.pw_gid > 0, 'follower and credential proxy need distinct unprivileged users')
    _, data, _ = paths(contract)
    for name in ('execution', 'consensus', 'bootstrap-cache'):
        path = data / name
        if path.exists():
            require(not path.is_symlink() and path.stat().st_uid == node.pw_uid, 'follower data has a different user owner')


def guard(state, role):
    check(state, state['contract'])
    validate_accounts(state['contract'])
    require(role in {'execution', 'consensus', 'rpc', 'upstreams', 'bootstrap'}, 'invalid service role')
    require(state.get('upstreams_installed'), 'upstream credentials are not installed')
    require(state['phase'] == ('bootstrapping' if role == 'bootstrap' else 'installed'), 'follower installation/bootstrap is incomplete or retired')
    if role != 'bootstrap':
        require(state.get('bootstrap_done'), 'bootstrap completion is not established')
    verify_identity(state)
    if role in {'execution', 'consensus'} and os.environ.get('CREDENTIALS_DIRECTORY'):
        runtime_identity(state, 'engine-jwt')
        runtime_identity(state, role + '-peer')
    capacity(state)
    verify_files(state)
    firewall(state)
    if role == 'rpc':
        require(inspect(state, gateway=False)['readiness']['ready'], 'follower is still synchronizing; RPC gateway remains closed')


def inspect(state, gateway=True):
    conf, _, _ = paths(state['contract'])
    if state['phase'] != 'installed' and not (conf / 'network.json').exists():
        return {'phase': state['phase'], 'contract': state['contract'], 'pair': state.get('pair'), 'target': state.get('target'),
                'bootstrap_done': state.get('bootstrap_done', False), 'readiness': {'ready': False, 'problems': ['not yet deployed']}}
    root_file(conf / 'network.json')
    expected = json.loads((conf / 'network.json').read_bytes())
    trusted_imports(LIB)
    import rollup_status
    services = {key: service_active(value) for key, value in units(state['contract']).items()}
    result = rollup_status.inspect(state, expected, services, gateway)
    try:
        verify_identity(state)
        verify_files(state)
        firewall(state)
    except Exception:
        result['readiness']['ready'] = False
        result['readiness']['problems'].append('protected configuration or firewall verification failed')
    return result


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def reset_bootstrap(state):
    require(state.get('bootstrap_done') is False, 'completed databases cannot be reset by bootstrap recovery')
    validate_accounts(state['contract'])
    if state.get('pair'):
        verify_identity(state)
    _, data, _ = paths(state['contract'])
    if 'reset' not in state:
        directory = 'bootstrap-recovery-' + str(time.time_ns())
        state['reset'] = {'directory': directory, 'bootstrap': state['bootstrap']}
    directory = state['reset'].get('directory')
    require(isinstance(directory, str) and re.fullmatch('bootstrap-recovery-[0-9]{1,30}', directory), 'invalid bootstrap recovery intent')
    cancel_deployment(state)
    state['phase'] = 'resetting'
    write_state(state)  # Every service guard refuses before stopping or moving data.
    stop(state['contract'])
    quarantine = data / directory
    require(not quarantine.is_symlink(), 'unsafe bootstrap recovery directory')
    quarantine.mkdir(mode=0o700, exist_ok=True)
    require(quarantine.stat().st_uid == OWNER_UID and quarantine.stat().st_mode & 0o077 == 0,
            'bootstrap recovery directory must remain private and root-owned')
    account = pwd.getpwnam('erpc-' + state['contract']['family'])
    for name in ('execution', 'bootstrap-cache'):
        source, saved = data / name, quarantine / name
        require(not source.is_symlink() and not saved.is_symlink(), 'unsafe bootstrap recovery path')
        if saved.exists():
            require(saved.is_dir() and (not source.exists() or (source.is_dir() and not any(source.iterdir()))),
                    'recovery source was modified after quarantine; inspect retained data')
        else:
            require(source.is_dir() and source.stat().st_dev == data.stat().st_dev, 'bootstrap recovery requires its original filesystem')
            os.rename(source, saved)
            sync_directory(data)
            sync_directory(quarantine)
        source.mkdir(mode=0o700, exist_ok=True)
        os.chown(source, account.pw_uid, account.pw_gid)
        os.chmod(source, 0o700)
        sync_directory(data)
    atomic(quarantine / 'recovery.json', json.dumps(state['reset'], sort_keys=True).encode())
    state['last_recovery'] = state.pop('reset')
    state.pop('target', None)
    state['phase'] = 'prepared'
    write_state(state)
    return {'phase': 'prepared', 'quarantine': str(quarantine), 'data_deleted': False}


def begin_install(state, request):
    require_deploy(state, request)
    if state.get('pair'):
        verify_identity(state)
    require('reset' not in state and state['phase'] != 'resetting', 'resume explicit bootstrap recovery before installation')
    require(state['phase'] != 'bootstrapping', 'resume or stop the existing bootstrap before changing clients')
    if not state.get('bootstrap_done'):
        validate_bootstrap(state['contract'], request['bootstrap'])
        if state['phase'] == 'prepared' or (state['phase'] == 'retired' and not state.get('pair')):
            state['bootstrap'] = request['bootstrap']
        else:
            require(state['bootstrap'] == request['bootstrap'], 'resume the same immutable bootstrap source')
    capacity(state)
    target = request['pair']
    require(isinstance(target, dict) and set(target) == {'architecture', 'execution', 'consensus'}, 'invalid client pair')
    for role in ('execution', 'consensus'):
        client = target[role]
        require(isinstance(client, dict) and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', client.get('version', '')),
                'invalid stable client version')
        if state.get('pair'):
            before = tuple(int(x) for x in state['pair'][role]['version'].split('.'))
            after = tuple(int(x) for x in client['version'].split('.'))
            require(after >= before, 'database/client downgrades are refused')
    if state['phase'] == 'installing':
        require(state['target'] == target, 'resume the interrupted target before changing clients')
    state.update(phase='installing', target=target)
    write_state(state)
    stop(state['contract'])
    return {'phase': 'installing'}


def finish_install(state, request):
    require_deploy(state, request)
    require(state['phase'] == 'installing' and state['target'] == request['pair'], 'installation target changed')
    require(state.get('upstreams_installed'), 'upstream credential provisioning is incomplete')
    verify_files(state)
    initialize_identity(state)
    state['pair'] = state.pop('target')
    state['phase'] = 'installed' if state['bootstrap_done'] else 'bootstrapping'
    write_state(state)
    return {'phase': state['phase']}


def start(state):
    names = units(state['contract'])
    if not state.get('bootstrap_done'):
        guard(state, 'bootstrap')
        run(['systemctl', 'daemon-reload'])
        run(['systemctl', 'enable', names['firewall'], names['bootstrap']])
        run(['systemctl', 'start', '--no-block', names['bootstrap']])
        return {'phase': 'bootstrapping', 'ready': False}
    guard(state, 'execution')
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'enable', names['firewall'], names['upstreams'], names['execution'], names['consensus'], names['rpc']])
    run(['systemctl', 'start', names['upstreams'], names['execution'], names['consensus']], timeout=660)
    run(['systemctl', 'start', '--no-block', names['rpc']])
    return {'phase': state['phase'], 'service_started': True, 'ready': False}


def dispatch(request):
    action = request.get('action')
    if action == 'check':
        return preflight(request['contract'])
    if action == 'prepare':
        return prepare(request)
    state = read_state()
    check(state, request['contract'])
    if action == 'authorize-deploy':
        return authorize_deploy(state, request)
    if action == 'check-deploy':
        require_deploy(state, request)
        return {'deployment_authorized': True}
    if action == 'reset-bootstrap':
        return reset_bootstrap(state)
    if action == 'validate-accounts':
        validate_accounts(state['contract'])
        return {'accounts_validated': True}
    if action == 'upstreams':
        return configure_upstreams(state, request)
    if action == 'begin-install':
        return begin_install(state, request)
    if action == 'finish-install':
        return finish_install(state, request)
    if action in {'start', 'restart'}:
        if 'intent' in request:
            require_deploy(state, request)
        if action == 'restart':
            guard(state, 'execution' if state.get('bootstrap_done') else 'bootstrap')
            cancel_deployment(state)
            write_state(state)
            stop(state['contract'])
        return start(state)
    if action in {'stop', 'destroy'}:
        cancel_deployment(state)
        write_state(state)
        if action == 'destroy':
            state['phase'] = 'retired'
            write_state(state)
        stop(state['contract'])
        for name in ('bootstrap', 'rpc', 'consensus', 'execution', 'upstreams'):
            run(['systemctl', 'disable', units(state['contract'])[name]], allowed=(0, 1))
        return {'phase': state['phase'], 'service_stopped': True, 'data_preserved': True}
    if action == 'status':
        return inspect(state)
    raise Refused('unsupported follower operation')


def wait_listener(engine):
    state = read_state()
    expected = '0x1' if state['contract']['network'] == 'mainnet' else '0xaa36a7'
    trusted_imports(LIB)
    import rollup_status
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        if engine:
            connection = http.client.HTTPConnection('127.0.0.1', 8551, timeout=5)
            try:
                connection.request('GET', '/')
                if connection.getresponse().status == 401:
                    return
            except Exception:
                pass
            finally:
                connection.close()
        elif rollup_status.rpc(18545, 'eth_chainId', []) == expected:
            return
        time.sleep(2)
    raise Refused('required local follower listener did not become available')


def main():
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    require(os.geteuid() == 0, 'root is required')
    if sys.argv[1:] in (['wait-engine'], ['wait-upstream']):
        wait_listener(sys.argv[1] == 'wait-engine')
        return
    if len(sys.argv) == 7 and sys.argv[1] == 'guard':
        role, owner, family, network, history = sys.argv[2:]
        state = read_state()
        check(state, {'owner': owner, 'family': family, 'network': network, 'history': history})
        guard(state, role)
        return
    raw = sys.stdin.buffer.read(1024 * 1024 + 1)
    require(len(raw) <= 1024 * 1024, 'controller request exceeds limit')
    request = json.loads(raw)
    # Ansible calls inside its existing /opt/erpc node-run lock. Ordinary SSH
    # mutators take that same directory lock before checking or writing state.
    if sys.argv[1:] == ['within-run']:
        print(json.dumps(dispatch(request)))
        return
    require(not sys.argv[1:], 'unsupported controller arguments')
    LOCK.mkdir(mode=0o755, parents=True, exist_ok=True)
    fd = os.open(LOCK, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        print(json.dumps(dispatch(request)))
    finally:
        os.close(fd)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Inputs may include provider credentials; no dynamic exception text.
        print('Follower operation refused or failed; inspect its owned state and journal', file=sys.stderr)
        sys.exit(1)
