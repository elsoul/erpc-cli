#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""TRON host ownership, credential custody and receipt-bound lifecycle boundary."""
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid
import identity
import observe


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


# ERPC deployment policy, distinct from the upstream 4 TB provision recommendation.
BOOTSTRAP_CAPACITY = 3_500_000_000_000
OPERATING_RESERVE = 64 * 1024 ** 3


def data_capacity(data, run=subprocess.run):
    if data.is_symlink() or not data.is_dir():
        raise ValueError('TRON data must be a dedicated real directory')
    device = data.stat().st_dev
    # A nested database mount would invalidate adding its usage to this volume's
    # free space. Mount the provisioned volume at /var/lib/tron instead.
    for child in data.iterdir():
        if child.is_symlink() or child.stat().st_dev != device:
            raise ValueError('TRON data children must remain on the reserved data filesystem')
    stats = os.statvfs(data)
    available = stats.f_bavail * stats.f_frsize
    used = run(['du', '-s', '-x', '--block-size=1', str(data)], check=True,
               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    amount = used.stdout.split(maxsplit=1)[0]
    if not amount.isdigit():
        raise ValueError('allocated data usage could not be established')
    return {'available_bytes': available, 'allocated_bytes': int(amount)}


def expected_contract(network, role, genesis, architecture, owner, signer, inventory_owner):
    if not re.fullmatch("[a-z0-9]{26}", inventory_owner):
        raise ValueError("a persisted inventory owner is required")
    if network not in ('mainnet', 'nile') or role not in ('fullnode', 'validator'):
        raise ValueError('unsupported TRON network or role')
    if architecture not in identity.JAVA or not re.fullmatch('[a-f0-9]{64}', genesis):
        raise ValueError('unsupported TRON host or genesis')
    owner, signer = '' if owner == '-' else owner, '' if signer == '-' else signer
    if role == 'validator':
        identity.address(owner)
        identity.address(signer)
        if owner == signer:
            raise ValueError('owner keys cannot be hosted')
    elif owner or signer:
        raise ValueError('a query node cannot hold witness credentials')
    return dict(network=network, role=role, genesis=genesis, architecture=architecture, owner=owner, signer=signer, inventory_owner=inventory_owner)


def reviewed_target(expected, target):
    fields = {'network', 'architecture', 'genesis', 'version', 'tag', 'commit', 'jar_sha256', 'config_sha256'}
    if not isinstance(target, dict) or set(target) != fields or any(not isinstance(v, str) for v in target.values()):
        raise ValueError('a complete reviewed release target is required')
    if any(target[k] != expected[k] for k in ('network', 'architecture', 'genesis')):
        raise ValueError('release target belongs to another host contract')
    for key, size in [('commit', 40), ('jar_sha256', 64), ('config_sha256', 64)]:
        if not re.fullmatch('[a-f0-9]{' + str(size) + '}', target[key]):
            raise ValueError('invalid reviewed release digest or commit')
    version_order(target['network'], target['version'])
    tag = 'GreatVoyage-v' + target['version'] if target['network'] == 'mainnet' else 'GreatVoyage-Nile-v' + target['version'].replace('.PQ', '-PQ').replace('_build', '-build')
    if target['tag'] != tag:
        raise ValueError('release tag and native version differ')
    return target


def version_order(network, version):
    pattern = r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)'
    if network == 'nile':
        pattern += r'\.PQ(0|[1-9][0-9]*)_build(0|[1-9][0-9]*)'
    match = re.fullmatch(pattern, version)
    if not match:
        raise ValueError('ambiguous release ordering requires a reviewed migration')
    return tuple(int(value) for value in match.groups())


def transition(expected, previous, desired):
    reviewed_target(expected, previous)
    old, new = version_order(expected['network'], previous['version']), version_order(expected['network'], desired['version'])
    if new < old or (new == old and previous != desired):
        raise ValueError('older or ambiguously changed release target is refused; no database downgrade')


class Control:
    def __init__(self, root=Path('/'), run=subprocess.run, firewall=None, query=observe.request, usage=data_capacity):
        self.root, self.run, self.query = root, run, query
        self.firewall_factory = firewall
        self.usage = usage

    def path(self, path):
        return self.root / path.lstrip('/')

    def read(self, path):
        return json.loads(self.path(path).read_text(), object_pairs_hook=identity.unique_object)

    def write(self, path, value):
        target = self.path(path)
        pending = target.with_suffix('.pending')
        with pending.open('w') as stream:
            json.dump(value, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(pending, target)

    def command(self, *args, check=True, **kwargs):
        return self.run(list(args), check=check, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)

    def contract(self, expected, initial=False):
        saved = self.path('/etc/tron/contract.json')
        if saved.is_symlink():
            raise ValueError('host contract must be a regular managed file')
        if not saved.exists():
            artifacts = [
                '/etc/systemd/system/tron-node.service', '/etc/tron/node.conf',
                '/etc/tron/identity.json', '/etc/tron/preparing', '/etc/tron/release.json',
                '/etc/tron/activation.json', '/etc/credstore.encrypted/tron',
                '/opt/tron/current',
            ]
            directories = [self.path(p) for p in ('/etc/tron', '/var/lib/tron', '/etc/erpc/tron')]
            retained = any(p.is_symlink() or (p.exists() and any(p.iterdir())) for p in directories)
            if not initial or retained or any(self.path(p).exists() or self.path(p).is_symlink() for p in artifacts):
                raise ValueError('missing host ownership with retained TRON material; explicit recovery is required')
            return
        if self.read('/etc/tron/contract.json') != expected:
            raise ValueError('TRON network, role or signing ownership differs')

    def firewall(self):
        if self.firewall_factory:
            return self.firewall_factory()
        source = self.path('/usr/local/lib/erpc/rpc-firewall.py')
        spec = importlib.util.spec_from_file_location('erpc_rpc_firewall', source)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.Firewall('tron', self.root, self.run)

    def capacity(self):
        value = self.usage(self.path('/var/lib/tron'), self.run)
        available, allocated = value['available_bytes'], value['allocated_bytes']
        if type(available) is not int or type(allocated) is not int or min(available, allocated) < 0:
            raise ValueError('data capacity observation is invalid')
        if available < OPERATING_RESERVE:
            raise ValueError('TRON requires 64 GiB of operating free space; stop/destroy remain available')
        if available + allocated < BOOTSTRAP_CAPACITY:
            raise ValueError('TRON requires 3.5 TB of free plus already allocated chain data capacity')
        return dict(value, bootstrap_capacity_bytes=BOOTSTRAP_CAPACITY, operating_reserve_bytes=OPERATING_RESERVE)

    def phase(self, expected, intent, target=None):
        self.contract(expected)
        record = self.read('/etc/tron/intent.json')
        if not intent or not re.fullmatch('[a-f0-9]{32}', intent) or record.get('intent') != intent:
            raise ValueError('this deployment was superseded or stopped')
        wanted = reviewed_target(expected, record.get('target'))
        if target is not None and reviewed_target(expected, target) != wanted:
            raise ValueError('this phase targets another release than the original intent')
        return wanted

    def invalidate(self, reason):
        record = self.read('/etc/tron/intent.json') if self.path('/etc/tron/intent.json').exists() else {}
        record['intent'] = reason + ':' + uuid.uuid4().hex
        self.write('/etc/tron/intent.json', record)  # Preserve an interrupted release's monotonic floor.

    def fence(self):
        self.path('/etc/tron/preparing').touch()

    def stop(self, disable=False):
        found = self.command('systemctl', 'show', '--property=LoadState', '--value', 'tron-node', check=False)
        state = found.stdout.decode().strip()
        if state == 'not-found':
            return
        if found.returncode or state not in ('loaded', 'masked'):
            raise ValueError('cannot determine the managed service state')
        if disable:
            self.command('systemctl', 'disable', '--now', 'tron-node')
        else:
            self.command('systemctl', 'stop', 'tron-node')
        self.stopped()

    def stopped(self):
        found = self.command('systemctl', 'show', '--property=LoadState', '--value', 'tron-node', check=False)
        if found.stdout.decode().strip() == 'not-found':
            return
        if found.returncode:
            raise ValueError('managed service state is unknown')
        active = self.command('systemctl', 'is-active', 'tron-node', check=False)
        if active.stdout.decode().strip() not in ('inactive', 'failed'):
            raise ValueError('stop the validator before touching its credentials')
        pid = self.command('systemctl', 'show', '--property=MainPID', '--value', 'tron-node')
        if pid.stdout.decode().strip() != '0':
            raise ValueError('the managed node has not finished draining')

    def verify_install(self, expected):
        release = self.read('/etc/tron/release.json')
        target = reviewed_target(expected, release.get('target'))
        if any(release.get(key) != target[field] for key, field in [('jar_sha256', 'jar_sha256'), ('config_sha256', 'config_sha256'), ('client_version', 'version')]):
            raise ValueError('installed release metadata differs from its reviewed target')
        if any(release.get(key) != expected[key] for key in ('network', 'architecture', 'genesis')):
            raise ValueError('installed release belongs to another host contract')
        name = release['directory']
        if name != '/opt/tron/releases/' + target['tag'] + '-' + expected['architecture']:
            raise ValueError('installed release path differs from the reviewed target')
        if not re.fullmatch('/opt/tron/releases/GreatVoyage-[A-Za-z0-9._-]+-(x86_64|aarch64)', name) or not name.endswith('-' + expected['architecture']):
            raise ValueError('invalid managed release directory')
        if self.path('/opt/tron/current').resolve() != self.path(name).resolve():
            raise ValueError('current client differs from the activated release')
        for filename, key in [('FullNode.jar', 'jar_sha256'), ('network.conf', 'config_sha256'), ('erpc/ErpcTronKey.class', 'inspector_sha256')]:
            if digest(self.path(name) / filename) != release[key]:
                raise ValueError('installed client/configuration changed after verification')
        if digest(self.path('/etc/tron/node.conf')) != release['node_config_sha256']:
            raise ValueError('node configuration differs from the reviewed deployment')
        return release

    def identity_receipt(self, expected, contents=True):
        receipt = self.read('/etc/tron/identity.json')
        if receipt.get('contract') != expected:
            raise ValueError('identity receipt belongs to another signer or network')
        generation = receipt['generation']
        if not re.fullmatch('[a-f0-9]{32}', generation):
            raise ValueError('invalid credential generation')
        directory = self.path('/etc/credstore.encrypted/tron/generations/' + generation)
        if contents:
            selected = self.path('/etc/credstore.encrypted/tron/current')
            if not selected.is_symlink() or selected.resolve() != directory.resolve():
                raise ValueError('credential generation is missing or differs; explicit restore is required')
            for name in ('witness.json', 'witness-password'):
                if digest(directory / name) != receipt[name]:
                    raise ValueError('encrypted credentials changed or are missing; explicit restore is required')
        return directory

    def decrypt(self, name):
        result = self.command('systemd-creds', 'decrypt', '--name=' + name,
                              str(self.path('/etc/credstore.encrypted/tron/current') / name), '-')
        if len(result.stdout) > (16384 if name == 'witness.json' else 1024):
            raise ValueError('decrypted credential exceeded its bound')
        return result.stdout.decode()

    def check_keys(self, expected):
        self.verify_install(expected)
        self.identity_receipt(expected)
        identity.inspect(self.decrypt('witness.json'), self.decrypt('witness-password'),
                         expected['signer'], expected['architecture'], run=self.run)
        return {'identity': 'matches-reserved-witness-address'}

    def permissions(self, expected):
        clock = self.command('timedatectl', 'show', '--property=NTPSynchronized', '--value')
        if clock.stdout.decode().strip() != 'yes':
            raise ValueError('a synchronized clock is required before using the Witness signer')
        observed = observe.registration(expected, self.query)
        if observed['membership'] == 'not-registered' or not observed['witness_permission_valid']:
            raise ValueError('register the candidate and delegate an exclusive Witness permission externally first')
        return observed

    def status(self, expected):
        active = self.command('systemctl', 'is-active', 'tron-node', check=False).stdout.decode().strip()
        result = {'service': active, 'ready': False,
                  'startup_fenced': self.path('/etc/tron/preparing').exists() or self.path('/etc/tron/stopped').exists()}
        try:
            result['data_capacity'] = self.capacity()
            release = self.verify_install(expected)
            result['release_verified'] = True
            result['observation'] = observe.local_state(expected, self.query)
            result['grpc_ready'] = observe.grpc(run=self.run)
            result['json_rpc_ready'] = observe.json_rpc(expected) if expected['role'] == 'fullnode' else None
            result['ready'] = active == 'active' and not result['startup_fenced'] and result['observation']['chain_ready'] and result['observation']['code_version'] == release['client_version'] and result['grpc_ready'] and (expected['role'] != 'fullnode' or result['json_rpc_ready'])
        except Exception:
            result['readiness_error'] = 'installation or fresh progressing correct-network observations are unavailable'
        if expected['role'] == 'validator':
            try:
                result['registration'] = observe.registration(expected, self.query)
            except Exception:
                result['registration'] = {'membership': 'unknown', 'witness_permission_valid': False}
            try:
                self.identity_receipt(expected)
                result['identity_receipt_valid'] = True
                result['clock_synchronized'] = self.command('timedatectl', 'show', '--property=NTPSynchronized', '--value').stdout.decode().strip() == 'yes'
            except Exception:
                result['identity_receipt_valid'], result['clock_synchronized'] = False, False
            result['producer_eligible'] = result['ready'] and result['identity_receipt_valid'] and result['clock_synchronized'] and result['registration']['membership'] == 'elected' and result['registration']['witness_permission_valid']
        return result

    def import_keys(self, expected, payload, restore=False):
        self.contract(expected)
        if expected['role'] != 'validator' or not self.path('/etc/tron/preparing').exists():
            raise ValueError('credential import requires a fenced validator preparation')
        self.stopped()
        self.verify_install(expected)
        if not isinstance(payload, dict) or set(payload) != {'keystore', 'password'}:
            raise ValueError('only the native encrypted keystore and its password are accepted')
        store = self.path('/etc/credstore.encrypted/tron')
        established = self.path('/etc/tron/identity.json').exists()
        if restore:
            self.identity_receipt(expected, contents=False)
        elif store.exists() or established:
            return self.check_keys(expected)  # Never overwrite an established signer implicitly.
        observed = self.permissions(expected)
        if not restore and observed['membership'] == 'elected':
            raise ValueError('an elected signer cannot be adopted by a new host; live migration is unsupported')
        text, password = payload['keystore'], payload['password']
        if not isinstance(text, str) or not isinstance(password, str):
            raise ValueError('invalid credential input')
        identity.inspect(text, password, expected['signer'], expected['architecture'], run=self.run)
        generation = uuid.uuid4().hex  # A public storage identifier, never a signing key.
        directory = store / 'generations' / generation
        directory.mkdir(parents=True, mode=0o700)
        receipt = {'contract': expected, 'generation': generation}
        for name, value in [('witness.json', text), ('witness-password', password)]:
            self.command('systemd-creds', 'encrypt', '--name=' + name, '-', str(directory / name), input=value.encode())
            receipt[name] = digest(directory / name)
        # A crash between receipt and pointer leaves the startup fence in place.
        # Explicit restore can use the original public receipt; old generations remain.
        self.write('/etc/tron/identity.json', receipt)
        pending = store / 'current.pending'
        pending.unlink(missing_ok=True)
        pending.symlink_to('generations/' + generation)
        os.replace(pending, store / 'current')
        return self.check_keys(expected)

    def runtime(self, expected, manual=False):
        self.contract(expected)
        self.capacity()
        if self.path('/etc/tron/preparing').exists():
            raise ValueError('TRON startup is fenced pending verified activation')
        if not manual and self.path('/etc/tron/stopped').exists():
            raise ValueError('operator stopped this node; use the explicit start command')
        activation = self.read('/etc/tron/activation.json')
        if activation['contract'] != expected:
            raise ValueError('activation belongs to another host contract')
        self.verify_install(expected)
        if digest(self.path('/etc/tron/release.json')) != activation['release']:
            raise ValueError('release changed after activation')
        self.firewall().require_confirmed(activation['run'], activation['bundle'])
        if expected['role'] == 'validator':
            self.identity_receipt(expected)  # No decrypt/TPM operation inside the service sandbox.
            self.permissions(expected)

    def activate(self, expected, intent, run, bundle, target):
        self.phase(expected, intent, target)
        self.firewall().require_confirmed(run, bundle)
        self.capacity()
        if self.verify_install(expected)['target'] != target:
            raise ValueError('installed release differs from the activation intent')
        if expected['role'] == 'validator':
            self.check_keys(expected)
            self.permissions(expected)
        self.write('/etc/tron/activation.json', {'contract': expected, 'intent': intent, 'run': run, 'bundle': bundle,
                                                'release': digest(self.path('/etc/tron/release.json'))})
        self.path('/etc/tron/preparing').unlink(missing_ok=True)
        self.path('/etc/tron/stopped').unlink(missing_ok=True)
        self.command('systemctl', 'daemon-reload')
        self.command('systemctl', 'enable', 'tron-node', 'erpc-tron-firewall')
        self.command('systemctl', 'start', '--no-block', 'tron-node')

    def dispatch(self, operation, expected, intent=None, receipt=None, payload=None, target=None):
        # These operations are invoked by a play already holding /opt/erpc's lock.
        if operation in ('guard-init', 'guard', 'guard-phase', 'prepare', 'activate', 'destroy', 'runtime'):
            self.contract(expected, initial=operation == 'guard-init')
            if operation == 'guard-phase':
                self.phase(expected, intent, reviewed_target(expected, target))
            elif operation == 'prepare':
                if not intent or not re.fullmatch('[a-f0-9]{32}', intent):
                    raise ValueError('a new deployment needs its own intent')
                target = reviewed_target(expected, target)
                if self.path('/etc/tron/release.json').exists():
                    transition(expected, self.read('/etc/tron/release.json').get('target'), target)
                if self.path('/etc/tron/intent.json').exists():
                    previous = self.read('/etc/tron/intent.json').get('target')
                    if previous is not None:
                        transition(expected, previous, target)
                self.capacity()
                self.write('/etc/tron/intent.json', {'intent': intent, 'target': target})
                self.fence()
                self.stop()
            elif operation == 'activate':
                self.activate(expected, intent, *receipt, target)
            elif operation == 'destroy':
                self.invalidate('destroyed')
                self.fence()
                self.stop(disable=True)
            elif operation == 'runtime':
                self.runtime(expected)  # Read-only systemd precondition; never acquires the parent lock.
            return {'operation': operation}
        lock = os.open(self.path('/opt/erpc'), os.O_RDONLY)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX)
            self.contract(expected)
            if operation in ('import', 'restore'):
                self.phase(expected, intent)
                return self.import_keys(expected, payload, restore=operation == 'restore')
            if operation == 'confirm':
                self.phase(expected, intent)
                self.firewall().confirm(*receipt)
                return {'firewall': 'confirmed'}
            if operation == 'validate-registration':
                self.check_keys(expected)
                return {'identity_verified': True, 'registration': self.permissions(expected)}
            if operation == 'check-keys':
                return self.check_keys(expected)
            if operation == 'registration':
                return observe.registration(expected, self.query)
            if operation == 'status':
                return self.status(expected)
            if operation == 'stop':
                self.invalidate('stopped')
                self.path('/etc/tron/stopped').touch()
                self.stop()
            elif operation in ('start', 'restart'):
                self.runtime(expected, manual=True)
                self.invalidate('manual-' + operation)
                self.path('/etc/tron/stopped').unlink(missing_ok=True)
                self.command('systemctl', operation, '--no-block', 'tron-node')
            else:
                raise ValueError('unsupported TRON operation')
            return {'operation': operation}
        finally:
            os.close(lock)


def main():
    os.umask(0o077)
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    operation = sys.argv[1] if len(sys.argv) > 1 else ''
    has_intent = operation in ('prepare', 'guard-phase', 'import', 'restore', 'activate', 'confirm')
    has_target = operation in ('prepare', 'guard-phase', 'activate')
    wanted = (12 if operation in ('activate', 'confirm') else 10 if has_intent else 9) + int(has_target)
    if len(sys.argv) != wanted:
        raise ValueError('expected operation and complete public host contract/receipt')
    expected = expected_contract(*sys.argv[2:9])
    intent = sys.argv[9] if has_intent else None
    receipt = sys.argv[10:12] if operation in ('activate', 'confirm') else None
    target = json.loads(sys.argv[-1], object_pairs_hook=identity.unique_object) if has_target else None
    payload = None
    if operation in ('import', 'restore'):
        data = sys.stdin.buffer.read(32769)
        if len(data) > 32768:
            raise ValueError('oversized credential import')
        payload = json.loads(data, object_pairs_hook=identity.unique_object)
    result = Control().dispatch(operation, expected, intent, receipt, payload, target)
    print(json.dumps(result))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('TRON operation refused: ownership, credentials, network or activation was not verified', file=sys.stderr)
        raise SystemExit(1)
