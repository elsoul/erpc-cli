#!/usr/bin/python3 -I
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
import stat
import sys
import uuid

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

if __name__ == '__main__':
    trusted_imports(Path(__file__).absolute().parent)
import identity
import observe
import host
import accounts


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
    def __init__(self, root=Path('/'), run=subprocess.run, firewall=None, query=observe.request, usage=data_capacity, proof=None, owner=0, account=None):
        self.root, self.run, self.query = root, run, query
        self.firewall_factory = firewall
        self.usage = usage
        self.owner=owner
        self.accounts=accounts.Accounts(self) if account is None else account
        self.proof=host.Proof(self) if proof is None else proof

    def path(self, path):
        return self.root / path.lstrip('/')

    def protected(self,path,missing=False):
        if not path.startswith('/') or any(part in ('.','..') for part in Path(path).parts):
            raise ValueError('protected host path must be absolute without traversal')
        current=self.root;parts=Path(path).parts[1:]
        for index,part in enumerate(parts):
            current=current/part
            try:info=current.lstat()
            except FileNotFoundError:
                if missing:return self.path(path)
                raise ValueError('protected host path is missing') from None
            if (info.st_uid!=self.owner or info.st_mode&0o022
                    or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
                    or index<len(parts)-1 and not stat.S_ISDIR(info.st_mode)
                    or stat.S_ISREG(info.st_mode) and info.st_nlink!=1):
                raise ValueError('protected host ownership or type is unsafe')
        return current

    def namespaces(self):
        # Validate existing destinations before any mkdir/copy/chown. Shared
        # directories are checked as ancestors, never recursively adopted.
        directories=('/etc/tron','/etc/erpc/tron','/etc/credstore.encrypted/tron',
            '/opt/tron/releases','/usr/local/lib/erpc/tron',
            '/etc/systemd/system/tron-node.service.d','/etc/systemd/system/erpc-tron-firewall.service.d')
        for name in directories:
            directory=self.protected(name,missing=True)
            if directory.exists() and not directory.is_dir():raise ValueError('privileged namespace is not a directory')
            if directory.exists():
                for root,children,files in os.walk(directory,followlinks=False):
                    for child in (*children,*files):
                        path=Path(root)/child;logical='/'+str(path.relative_to(self.root))
                        if logical in ('/etc/tron/credentials','/etc/credstore.encrypted/tron/current','/etc/credstore.encrypted/tron/current.pending'):
                            self.pointer(logical)
                        else:self.protected(logical)
        for name in ('/usr/local/lib/erpc/rpc-firewall.py','/etc/systemd/system/tron-node.service',
                '/etc/systemd/system/erpc-tron-firewall.service','/etc/systemd/system/tron-node.service.d',
                '/etc/systemd/system/erpc-tron-firewall.service.d',
                '/etc/systemd/system/tron-node.service.d/erpc-rpc-firewall.conf'):
            self.protected(name,missing=True)
        self.protected('/opt/tron',missing=True)
        if self.path('/opt/tron/current').exists() or self.path('/opt/tron/current').is_symlink():self.pointer('/opt/tron/current')
        for name in ('/var/lib','/var/log'):self.protected(name,missing=True)
        for name in ('/var/lib/tron','/var/log/tron'):
            path=self.path(name)
            if path.is_symlink() or path.exists() and not path.is_dir():raise ValueError('runtime data/log namespace is redirected')
            if path.exists():
                info=path.stat();retained=self.accounts.retained_uid()
                if info.st_uid not in {self.owner,retained} or info.st_mode&0o022:
                    raise ValueError('runtime directory has no original ownership authority')

    def pointer(self,name):
        path=self.path(name);info=path.lstat()
        if not stat.S_ISLNK(info.st_mode) or info.st_uid!=self.owner:raise ValueError('managed pointer is unsafe')
        target=os.readlink(path)
        if self.root!=Path('/') and target.startswith(str(self.root)+'/'):
            target='/'+str(Path(target).relative_to(self.root))
        if name=='/etc/tron/credentials':
            if target!='/run/credentials/tron-node.service':raise ValueError('credential runtime pointer changed')
        elif name=='/opt/tron/current':
            if not re.fullmatch('/opt/tron/releases/GreatVoyage-[A-Za-z0-9._-]+-(x86_64|aarch64)',target):
                raise ValueError('release pointer target is not a fixed managed version')
            self.protected(target)
        else:
            if not re.fullmatch('generations/[a-f0-9]{32}',target):raise ValueError('credential pointer target changed')
            self.protected('/etc/credstore.encrypted/tron/'+target)

    def read(self, path):
        return json.loads(self.protected(path).read_text(), object_pairs_hook=identity.unique_object)

    def write(self,path,value,mode=0o600):
        target=self.protected(path,missing=True);pending=target.with_suffix('.pending')
        self.protected('/'+str(pending.relative_to(self.root)),missing=True)
        descriptor=os.open(pending,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,mode)
        with os.fdopen(descriptor,'w') as stream:
            os.fchmod(stream.fileno(),mode);json.dump(value,stream,sort_keys=True)
            stream.flush();os.fsync(stream.fileno())
        host.publish(pending,target,stop=self.root)

    def command(self, *args, check=True, **kwargs):
        kwargs.setdefault('env',{'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/root','LANG':'C.UTF-8'})
        return self.run(list(args), check=check, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)

    def contract(self, expected, initial=False):
        if initial:
            self.namespaces();self.accounts.preflight(expected)
        saved = self.protected('/etc/tron/contract.json',missing=True)
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
            self.proof.initial()
            directory=self.protected('/etc/tron',missing=True);directory.mkdir(parents=True,exist_ok=True,mode=0o755)
            host.sync_parents(directory,self.root)
            self.write('/etc/tron/contract.json',expected)
            return
        if self.read('/etc/tron/contract.json') != expected:
            raise ValueError('TRON network, role or signing ownership differs')

    def firewall(self):
        if self.firewall_factory:
            return self.firewall_factory()
        source = self.protected('/usr/local/lib/erpc/rpc-firewall.py')
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
        if self.path('/etc/tron/stopped').exists():
            raise ValueError('this deployment was explicitly stopped')
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
        host.fence(self.protected('/etc/tron/preparing',missing=True),self.root)

    def stop(self,disable=False):
        found=self.command('systemctl','show','--property=LoadState','--value','tron-node',check=False)
        state=found.stdout.decode().strip()
        if found.returncode or state not in ('loaded','masked','not-found'):
            raise ValueError('cannot determine the managed service state')
        active=self.command('systemctl','is-active','tron-node',check=False).stdout.decode().strip()
        pid=self.command('systemctl','show','--property=MainPID','--value','tron-node').stdout.decode().strip()
        if state!='not-found' or active not in ('inactive','failed') or pid!='0':
            self.command('systemctl',*(['disable','--now'] if disable else ['stop']),'tron-node')
        self.stopped()

    def cancel(self,retire=False):
        failure=None
        try:
            host.fence(self.protected('/etc/tron/stopped',missing=True),self.root)
            if retire:self.fence()
        except Exception as error:failure=error
        try:self.invalidate('destroyed' if retire else 'stopped')
        except Exception as error:
            if failure is None:failure=error
        # Storage failure never skips the attempt to disable/drain known units.
        # Retain ingress and report uncertainty rather than claiming success.
        self.stop(disable=retire or failure is not None)
        if failure is not None:raise failure

    def stopped(self):
        found=self.command('systemctl','show','--property=LoadState','--value','tron-node',check=False)
        if found.returncode:raise ValueError('managed service state is unknown')
        active=self.command('systemctl','is-active','tron-node',check=False).stdout.decode().strip()
        pid=self.command('systemctl','show','--property=MainPID','--value','tron-node').stdout.decode().strip()
        if active not in ('inactive','failed') or pid!='0':raise ValueError('the managed node has not finished draining')
        self.proof.quiescent();self.proof.unoccupied()

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
            if digest(self.protected(name+'/'+filename)) != release[key]:
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
            self.accounts.verify(expected)
            release = self.authorized_install(expected)
            before=self.proof.listener(expected,release)
            result['release_verified'] = True
            result['observation'] = observe.local_state(expected, self.query)
            result['grpc_ready'] = observe.grpc(run=self.run)
            result['json_rpc_ready'] = observe.json_rpc(expected) if expected['role'] == 'fullnode' else None
            if self.proof.listener(expected,release)!=before:raise ValueError('native listener changed during health sampling')
            result['listener_owned']=True
            result['ready'] = active == 'active' and not result['startup_fenced'] and result['observation']['chain_ready'] and result['observation']['code_version'] == release['client_version'] and result['grpc_ready'] and (expected['role'] != 'fullnode' or result['json_rpc_ready'])
        except Exception:
            result['listener_owned']=False
            result['readiness_error'] = 'installation, owned native listeners or fresh correct-network observations are unavailable'
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
        established = self.path('/etc/tron/identity.json').exists() or self.path('/etc/tron/identity.json').is_symlink()
        if restore:
            self.identity_receipt(expected, contents=False)
        elif established:
            return self.check_keys(expected)  # Never overwrite an established signer implicitly.
        elif store.exists() or store.is_symlink():
            marker=self.read('/etc/tron/credential-preparation.json')
            data=self.path('/var/lib/tron');selected=store/'current'
            activation=self.path('/etc/tron/activation.json')
            if (marker!={'format':1,'contract':expected} or selected.exists() or selected.is_symlink()
                    or activation.exists() or activation.is_symlink() or data.is_symlink()
                    or data.exists() and any(data.iterdir())):
                raise ValueError('incomplete original custody has prior activation/history; explicit recovery required')
            self.protected('/etc/credstore.encrypted/tron')
            # Only our durably marked, never-selected initial attempt can resume.
            # Keep its unused ciphertexts; a fresh generation never adopts them.
        else:
            activation=self.path('/etc/tron/activation.json');data=self.path('/var/lib/tron')
            if activation.exists() or activation.is_symlink() or data.is_symlink() or data.exists() and any(data.iterdir()):
                raise ValueError('retained native history has lost its original custody receipt')
            self.write('/etc/tron/credential-preparation.json',{'format':1,'contract':expected})
        observed = self.permissions(expected)
        if not restore and observed['membership'] == 'elected':
            raise ValueError('an elected signer cannot be adopted by a new host; live migration is unsupported')
        text, password = payload['keystore'], payload['password']
        if not isinstance(text, str) or not isinstance(password, str):
            raise ValueError('invalid credential input')
        identity.inspect(text, password, expected['signer'], expected['architecture'], run=self.run)
        generation = uuid.uuid4().hex  # A public storage identifier, never a signing key.
        directory = self.protected('/etc/credstore.encrypted/tron/generations/'+generation,missing=True)
        directory.mkdir(parents=True, mode=0o700)
        receipt = {'contract': expected, 'generation': generation}
        for name, value in [('witness.json', text), ('witness-password', password)]:
            self.command('systemd-creds', 'encrypt', '--name=' + name, '-', str(directory / name), input=value.encode())
            receipt[name] = digest(directory / name)
        # A crash between receipt and pointer leaves the startup fence in place.
        # Explicit restore can use the original public receipt; old generations remain.
        host.sync_tree(directory);host.sync_parents(directory,self.root)
        self.write('/etc/tron/identity.json', receipt)
        pending = store / 'current.pending'
        pending.unlink(missing_ok=True)
        pending.symlink_to('generations/' + generation)
        os.replace(pending, store / 'current');host.sync_parents(store,self.root)
        return self.check_keys(expected)

    def authorized_install(self,expected):
        activation=self.read('/etc/tron/activation.json')
        if activation['contract']!=expected:raise ValueError('activation belongs to another host contract')
        release=self.verify_install(expected)
        if digest(self.path('/etc/tron/release.json'))!=activation['release']:
            raise ValueError('release changed after activation')
        self.firewall().require_confirmed(activation['run'],activation['bundle'])
        return release

    def runtime(self,expected,manual=False):
        self.contract(expected);self.namespaces();self.accounts.verify(expected);self.capacity()
        if self.path('/etc/tron/preparing').exists():raise ValueError('TRON startup is fenced pending verified activation')
        if not manual and self.path('/etc/tron/stopped').exists():raise ValueError('operator stopped this node; use explicit start')
        release=self.authorized_install(expected)
        if not manual:self.proof.startable()
        if expected['role']=='validator':
            self.identity_receipt(expected)
            self.permissions(expected)
        return release

    def activate(self, expected, intent, run, bundle, target):
        self.phase(expected, intent, target)
        self.namespaces();self.accounts.verify(expected)
        self.stopped()
        self.firewall().require_confirmed(run, bundle)
        self.capacity()
        if self.verify_install(expected)['target'] != target:
            raise ValueError('installed release differs from the activation intent')
        if expected['role'] == 'validator':
            self.check_keys(expected)
            self.permissions(expected)
        self.write('/etc/tron/activation.json', {'contract': expected, 'intent': intent, 'run': run, 'bundle': bundle,
                                                'release': digest(self.path('/etc/tron/release.json'))})
        host.unlink(self.protected('/etc/tron/preparing',missing=True),self.root)
        host.unlink(self.protected('/etc/tron/stopped',missing=True),self.root)
        self.command('systemctl', 'daemon-reload')
        self.command('systemctl', 'enable', 'tron-node', 'erpc-tron-firewall')
        self.command('systemctl', 'start', '--no-block', 'tron-node')

    def dispatch(self, operation, expected, intent=None, receipt=None, payload=None, target=None):
        operation={'start-v2':'start','stop-v2':'stop','restart-v2':'restart'}.get(operation,operation)
        # These operations are invoked by a play already holding /opt/erpc's lock.
        if operation in ('guard-init', 'guard', 'guard-stop', 'provision-account', 'guard-phase', 'prepare', 'activate', 'destroy', 'stop-play', 'runtime'):
            self.contract(expected, initial=operation == 'guard-init')
            if operation not in ('destroy','stop-play','guard-stop'):
                self.namespaces()
                if operation not in ('guard-init','provision-account'):self.accounts.verify(expected)
            if operation=='provision-account':self.accounts.provision(expected)
            if operation in ('guard-init','guard'):
                host.sync_file(self.protected('/etc/tron/contract.json'));host.sync_parents(self.path('/etc/tron'),self.root)
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
                if (self.path('/etc/tron/stopped').exists() and self.path('/etc/tron/intent.json').exists()
                        and self.read('/etc/tron/intent.json').get('intent')==intent):
                    raise ValueError('cancelled preparation requires a new deployment intent')
                self.write('/etc/tron/intent.json', {'intent': intent, 'target': target})
                self.fence()
                self.stop()
                host.unlink(self.protected('/etc/tron/stopped',missing=True),self.root)
            elif operation == 'activate':
                self.activate(expected, intent, *receipt, target)
            elif operation in ('destroy','stop-play'):
                self.cancel(retire=operation=='destroy')
            elif operation == 'runtime':
                self.runtime(expected)  # Read-only systemd precondition; never acquires the parent lock.
            return {'operation': operation}
        lock = os.open(self.path('/opt/erpc'), os.O_RDONLY)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX)
            self.contract(expected)
            if operation in ('import', 'restore'):
                self.phase(expected, intent)
                self.namespaces();self.accounts.verify(expected)
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
                self.cancel()
            elif operation in ('start','restart'):
                release=self.runtime(expected,manual=True)
                if operation=='restart':
                    host.fence(self.protected('/etc/tron/stopped',missing=True),self.root)
                    self.invalidate('manual-restart');self.stop()
                else:
                    self.proof.can_start(expected,release);self.invalidate('manual-start')
                host.unlink(self.protected('/etc/tron/stopped',missing=True),self.root)
                self.command('systemctl','start','--no-block','tron-node')
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
        print('TRON operation refused: ownership, process, storage, credentials or activation was not verified', file=sys.stderr)
        raise SystemExit(1)
