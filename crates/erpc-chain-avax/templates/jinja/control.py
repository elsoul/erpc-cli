#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original Avalanche authority; protected receipts precede custody delivery."""
import base64
import fcntl
import hashlib
import importlib.util
import importlib.machinery
import json
import os
import pathlib
import re
import resource
import stat
import subprocess
import sys
import time

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

if __name__=='__main__':trusted_imports(pathlib.Path(__file__).absolute().parent)
_loader=importlib.machinery.SourceFileLoader('avax_original_account',str(pathlib.Path(__file__).with_name('account.py')))
_spec=importlib.util.spec_from_loader(_loader.name,_loader)
account=importlib.util.module_from_spec(_spec);_loader.exec_module(account)

NAMES=('staker.crt','staker.key','signer.key')
UNITS=('avalanche-rpc.service','avalanchego.service')

class Control:
    Refused=ValueError
    def __init__(self, root=pathlib.Path('/'), run=subprocess.run, owner=0):
        self.root,self.run,self.owner=root,run,owner
        self.ROOT,self.TRUST_ANCHOR=self.path('/etc/avalanchego'),root
    def path(self,name):return self.root/name.lstrip('/')
    @staticmethod
    def require(value,message):
        if not value:raise ValueError(message)
    def command(self,*args,check=True):
        return self.run(list(args),check=check,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
    def durable_json(self,name,resync=True):
        path=self.protected(name)
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as stream:
            info=os.fstat(stream.fileno())
            self.require(stat.S_ISREG(info.st_mode) and info.st_uid==self.owner and info.st_nlink==1 and
                         not info.st_mode&0o022 and info.st_size<=1048576,'protected Avalanche receipt changed')
            raw=stream.read(1048577)
            self.require(len(raw)==info.st_size,'Avalanche receipt changed while read')
            if resync:os.fsync(stream.fileno())
        if resync:self.sync(path.parent)
        return json.loads(raw)

    def save(self,state):self.write('/etc/avalanchego/original-account.json',state)

    def protected(self, name, missing=False, directory=False):
        """Authenticate every real ancestor; never repair an unknown writable path."""
        target = self.path(name)
        current = self.root
        anchor = current.lstat()
        if not stat.S_ISDIR(anchor.st_mode) or anchor.st_uid != self.owner or anchor.st_mode & 0o022:
            raise ValueError('Avalanche trust anchor is unsafe')
        parts = target.relative_to(self.root).parts
        for index, part in enumerate(parts):
            current = current / part
            try:
                info = current.lstat()
            except FileNotFoundError:
                if missing:
                    return target
                raise
            last = index == len(parts) - 1
            if info.st_uid != self.owner or info.st_mode & 0o022:
                raise ValueError('Avalanche protected path is not owned exclusively by root')
            if not last or directory:
                if not stat.S_ISDIR(info.st_mode):
                    raise ValueError('Avalanche protected ancestor is not a real directory')
            elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError('Avalanche protected state must be a regular single-link file')
        return target

    def sync(self, directory):
        while True:
            descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            if directory == self.root:
                break
            directory = directory.parent

    def write(self, name, value, mode=0o600):
        target = self.protected(name, missing=True)
        pending = self.protected(name + '.pending', missing=True)
        with open(pending, 'w', encoding='utf-8') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(json.dumps(value, sort_keys=True))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(pending, target)
        self.sync(target.parent)

    def write_text(self, name, text):
        target = self.protected(name, missing=True)
        pending = self.protected(name + '.pending', missing=True)
        with open(pending, 'w', encoding='utf-8') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(text); stream.flush(); os.fsync(stream.fileno())
        os.replace(pending, target); self.sync(target.parent)

    def remove(self, name):
        target = self.protected(name, missing=True)
        if target.exists():
            target.unlink(); self.sync(target.parent)

    def quiet_uid(self, uid):
        if type(uid) is not int or not 100 <= uid <= 2147483647 or uid == 65534:
            raise ValueError('original Avalanche UID is unavailable for shutdown verification')
        proc = self.path('/proc')
        if not proc.is_dir():
            raise ValueError('process authority is unavailable')
        for process in proc.iterdir():
            if not process.name.isdecimal():
                continue
            try:
                info = process.lstat()
            except FileNotFoundError:
                continue
            if info.st_uid == uid:
                raise ValueError('an original Avalanche process remains; data and filtering retained')

    def fresh_home_entries(self, descriptor):
        entries = os.listdir(descriptor)
        if not entries:
            return
        if entries != ['lost+found']:
            raise ValueError('unowned Avalanche data cannot be adopted')
        recovery = os.open('lost+found', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                           dir_fd=descriptor)
        try:
            info = os.fstat(recovery)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != self.owner
                    or info.st_mode & 0o022 or os.listdir(recovery)):
                raise ValueError('unowned filesystem recovery content cannot be adopted')
            named = os.stat('lost+found', dir_fd=descriptor, follow_symlinks=False)
            if (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino):
                raise ValueError('filesystem recovery directory changed during qualification')
        finally:
            os.close(recovery)

    def fresh_home_descriptor(self, descriptor, record=None):
        info = os.fstat(descriptor)
        root_owned = info.st_uid == self.owner and not info.st_mode & 0o022
        original = (record is not None and info.st_uid == record['service_uid']
                    and info.st_gid == record['service_gid'] and stat.S_IMODE(info.st_mode) == 0o700)
        if not stat.S_ISDIR(info.st_mode) or not (root_owned or original):
            raise ValueError('fresh Avalanche data root has untrusted ownership or permissions')
        self.fresh_home_entries(descriptor)
        return info

    def fresh_home(self):
        self.protected('/var/lib', directory=True)
        home = self.path('/var/lib/avalanchego')
        if not home.exists() and not home.is_symlink():
            return
        descriptor = os.open(home, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = self.fresh_home_descriptor(descriptor)
            named = home.lstat()
            if (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino):
                raise ValueError('fresh Avalanche data path changed during qualification')
        finally:
            os.close(descriptor)

    def data_home(self, record, prepare=False):
        self.protected('/var/lib', directory=True)
        home = self.path('/var/lib/avalanchego')
        if record.get('home_established') is not True:
            if not prepare:
                raise ValueError('original Avalanche data home is not established')
            self.quiet_uid(record['service_uid'])
            if not home.exists() and not home.is_symlink():
                home.mkdir(mode=0o700)
            descriptor = os.open(home, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                info = self.fresh_home_descriptor(descriptor, record)
                named = home.lstat()
                if (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino):
                    raise ValueError('fresh Avalanche data path was replaced')
                # Only the qualified empty root-owned volume (or the exact
                # interrupted original reservation) may change ownership/mode.
                os.fchmod(descriptor, 0o700)
                os.fchown(descriptor, record['service_uid'], record['service_gid'])
                os.fsync(descriptor)
                named = home.lstat()
                if (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino):
                    raise ValueError('prepared Avalanche data path was replaced')
            finally:
                os.close(descriptor)
            self.sync(home.parent)
            record['home_established'] = True
            self.save(record)
        info = home.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != record['service_uid']
                or info.st_gid != record['service_gid'] or stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError('original Avalanche data root ownership or mode changed')


    def namespaces(self):
        for directory in ('/etc/avalanchego','/etc/erpc/avax','/opt/avalanchego','/opt/erpc',
                          '/usr/local/lib/erpc/avax','/etc/systemd/system'):
            self.protected(directory,missing=True,directory=True)
        for directory in ('/etc/avalanchego','/etc/erpc/avax'):
            parent=self.path(directory)
            if parent.exists():
                for entry in parent.rglob('*'):
                    self.protected(str(entry.relative_to(self.root)),directory=entry.is_dir() and not entry.is_symlink())
        native=self.path('/opt/avalanchego')
        if native.exists():
            for entry in native.rglob('*'):
                if entry==native/'current':
                    info=entry.lstat()
                    self.require(stat.S_ISLNK(info.st_mode) and info.st_uid==self.owner and
                                 re.fullmatch(r'/opt/avalanchego/v1[.]15[.][0-9]+',os.readlink(entry)) is not None,
                                 'native Avalanche release pointer changed')
                else:self.protected(str(entry.relative_to(self.root)),directory=entry.is_dir() and not entry.is_symlink())
        for name in ('avax-identity.py','avax-firewall.py','rpc-firewall.py'):
            self.protected('/usr/local/lib/erpc/'+name,missing=True)
        namespace=self.path('/usr/local/lib/erpc/avax')
        if namespace.exists():
            for entry in namespace.iterdir():
                self.require(entry.name in ('control.py','account.py','capacity.py','observe.py'),'unknown Avalanche helper entry')
                self.protected(str(entry.relative_to(self.root)))
        for unit in (*UNITS,'erpc-avax-firewall.service'):
            self.protected('/etc/systemd/system/'+unit,missing=True)
            folder=self.protected('/etc/systemd/system/'+unit+'.d',missing=True,directory=True)
            if folder.exists():
                for entry in folder.iterdir():
                    self.require(entry.name in ('50-erpc-firewall-guard.conf','50-erpc-firewall-guard.conf.new'),
                                 'unknown Avalanche service override')
                    self.protected(str(entry.relative_to(self.root)))

    def contract(self,expected,initial=False):
        self.namespaces()
        self.require(set(expected)=={'network','type','validator','owner'} and isinstance(expected['owner'],str) and re.fullmatch('[a-f0-9]{64}',expected['owner']) and expected['network'] in ('mainnet','fuji') and
                     expected['type'] in ('full','archive') and type(expected['validator']) is bool,'invalid Avalanche scope')
        path=self.protected('/etc/avalanchego/contract.json',missing=True)
        if not path.exists():
            if initial:
                receipt=self.path('/etc/avalanchego/original-account.json')
                if not receipt.exists():
                    self.fresh_home()
                    self.require(not any(self.path(name).exists() or self.path(name).is_symlink() for name in (
                        '/usr/local/lib/erpc/avax','/usr/local/lib/erpc/avax-identity.py','/usr/local/lib/erpc/avax-firewall.py',
                        '/etc/avalanchego/identity.json','/etc/avalanchego/generation-authorized','/etc/avalanchego/generation-started',
                        '/etc/avalanchego/lifecycle.json','/etc/avalanchego/stopped','/etc/avalanchego/native.json','/etc/avalanchego/gateway.json','/etc/avalanchego/database-floor.json')),
                        'orphan Avalanche managed artifacts cannot be adopted')
                    pending=self.protected('/etc/avalanchego/original-account.json.pending',missing=True)
                    if pending.exists():
                        value=json.loads(pending.read_text())
                        self.require(value.get('contract')==expected and value.get('protocol')==2,
                                     'interrupted original reservation belongs to another scope')
                else:
                    reservation=json.loads(self.protected('/etc/avalanchego/original-account.json').read_text())
                    self.require(reservation.get('contract')==expected and reservation.get('protocol')==2,
                                 'partial Avalanche reservation belongs to another scope')
                self.require(not any(self.path(p).exists() for p in (
                    '/etc/systemd/system/avalanchego.service','/etc/systemd/system/avalanche-rpc.service',
                    '/etc/avalanchego/node.json','/var/lib/avalanchego/db','/var/lib/avalanchego/staking')),
                    'unowned Avalanche installation cannot be adopted')
                return
            raise ValueError('Avalanche ownership is absent')
        stored=json.loads(path.read_text())
        self.require(isinstance(stored,dict) and type(stored.get('validator')) is bool,'invalid Avalanche stored scope')
        protocol=stored.pop('authority_protocol',None)
        record=stored.pop('original_account',None)
        self.require((stored==expected and protocol==2) or (protocol is None and stored=={k:v for k,v in expected.items() if k!='owner'}),'Avalanche inventory owner, network, role or history scope differs')
        if protocol==2:
            self.require(isinstance(record,dict) and record.get('contract')==expected and record.get('protocol')==2,
                         'original Avalanche account reservation changed')

    def account_record(self,expected,durable=True):
        self.contract(expected,initial=True)
        path=self.protected('/etc/avalanchego/original-account.json',missing=True)
        contract=self.protected('/etc/avalanchego/contract.json',missing=True)
        embedded=self.durable_json('/etc/avalanchego/contract.json',resync=durable).get('original_account') if contract.exists() else None
        record=self.durable_json('/etc/avalanchego/original-account.json',resync=durable) if path.exists() else embedded
        self.require(isinstance(record,dict) and record.get('contract')==expected and record.get('protocol')==2 and
                     (embedded is None or embedded==record),'original Avalanche account receipt is missing or changed')
        return record

    def account(self,expected):
        record=self.account_record(expected)
        account.verify(self,record);self.data_home(record)
        return record

    def prepare(self,expected):
        self.contract(expected,initial=True)
        path=self.path('/etc/avalanchego/contract.json')
        receipt=self.path('/etc/avalanchego/original-account.json')
        if receipt.exists() or path.exists() and json.loads(path.read_text()).get('original_account') is not None:
            record=self.account_record(expected)
        else:
            self.require(not path.exists(),'legacy Avalanche account requires explicit verified migration')
            record=dict(account.reserve(self),contract=expected,protocol=2,service_home='/var/lib/avalanchego',
                        account_established=False,home_established=False)
            self.protected('/etc/avalanchego',missing=True,directory=True).mkdir(mode=0o755,exist_ok=True)
            self.sync(self.ROOT);self.save(record)
        account.provision(self,record);self.data_home(record,prepare=True)
        self.write('/etc/avalanchego/contract.json',dict(expected,authority_protocol=2,original_account=record),mode=0o644)
        staking=self.path('/var/lib/avalanchego/staking')
        if not staking.exists():
            self.quiet_uid(record['service_uid'])
            staking.mkdir(mode=0o700)
            fd=os.open(staking,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:os.fchown(fd,record['service_uid'],record['service_gid']);os.fsync(fd)
            finally:os.close(fd)
            self.sync(staking.parent)
        self.staking(record)
        return {'uid':record['service_uid'],'gid':record['service_gid']}

    def staking(self,record):
        self.data_home(record)
        directory=self.path('/var/lib/avalanchego/staking');info=directory.lstat()
        self.require(stat.S_ISDIR(info.st_mode) and info.st_uid==record['service_uid'] and info.st_gid==record['service_gid'] and
                     stat.S_IMODE(info.st_mode)==0o700,'original Avalanche staking directory changed')
        return directory

    def identity_bytes(self,record,required=True):
        directory=self.staking(record);values={}
        for name in NAMES:
            path=directory/name
            if not path.exists() and not path.is_symlink() and not required:continue
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
            with os.fdopen(fd,'rb') as stream:
                before=os.fstat(stream.fileno())
                self.require(stat.S_ISREG(before.st_mode) and before.st_uid==record['service_uid'] and
                             before.st_nlink==1 and not before.st_mode&0o077 and 0<before.st_size<65536,
                             'Avalanche identity file authority differs')
                value=stream.read(65536);after=os.fstat(stream.fileno())
                self.require(len(value)==before.st_size and (before.st_ino,before.st_size,before.st_mtime_ns)==
                             (after.st_ino,after.st_size,after.st_mtime_ns),'Avalanche identity changed while read')
                os.fsync(stream.fileno())
                values[name]=value
        self.sync(directory)
        return values

    @staticmethod
    def digests(values):return {name:hashlib.sha256(data).hexdigest() for name,data in values.items()}

    def receipt(self,expected):
        value=self.durable_json('/etc/avalanchego/identity.json')
        self.require(value.get('contract')==expected and set(value.get('hashes',{}))==set(NAMES) and
                     all(re.fullmatch('[a-f0-9]{64}',digest) for digest in value['hashes'].values()),
                     'original Avalanche identity receipt is unavailable or changed')
        return value['hashes']

    def verify_identity(self,expected):
        record=self.account(expected);original=self.receipt(expected)
        values=self.identity_bytes(record)
        self.require(self.digests(values)==original,'Avalanche identity differs from original receipt')
        return values

    def authorize(self,expected):
        record=self.account(expected)
        if self.path('/etc/avalanchego/identity.json').exists():
            self.verify_identity(expected);return
        values=self.identity_bytes(record,False)
        if self.path('/etc/avalanchego/generation-started').exists():
            self.require(self.durable_json('/etc/avalanchego/generation-started')=={'contract':expected},
                         'interrupted generation belongs to another scope')
            self.quiet_uid(record['service_uid'])
            if values:
                # Generation was explicitly reserved before native execution.
                # Preserve a complete original readonly set after a failed root
                # manifest publication; never fill in a partial key set.
                self.require(set(values)==set(NAMES) and all(stat.S_IMODE((self.staking(record)/name).lstat().st_mode)==0o400
                                 for name in NAMES),'interrupted Avalanche identity is incomplete')
                self.seal(expected);self.verify_identity(expected);return
            self.remove('/etc/avalanchego/generation-started')
        self.require(not values,'unowned Avalanche identity cannot be adopted')
        self.write('/etc/avalanchego/generation-authorized',{'contract':expected})

    def generation_guard(self,expected):
        record=self.account(expected)
        self.lifecycle_ready(expected)
        if self.path('/etc/avalanchego/identity.json').exists():
            self.verify_identity(expected);return
        authorized=json.loads(self.protected('/etc/avalanchego/generation-authorized').read_text())
        self.require(authorized=={'contract':expected} and not self.path('/etc/avalanchego/generation-started').exists() and
                     not self.identity_bytes(record,False),'Avalanche identity generation was already consumed')
        self.write('/etc/avalanchego/generation-started',{'contract':expected})
        self.remove('/etc/avalanchego/generation-authorized')

    def seal(self,expected):
        record=self.account(expected)
        if self.path('/etc/avalanchego/identity.json').exists():self.verify_identity(expected);return
        started=json.loads(self.protected('/etc/avalanchego/generation-started').read_text())
        self.require(started=={'contract':expected},'Avalanche generation authorization differs')
        for _ in range(60):
            complete=True
            for name in NAMES:
                try:info=(self.staking(record)/name).lstat()
                except FileNotFoundError:complete=False;continue
                self.require(stat.S_ISREG(info.st_mode) and info.st_uid==record['service_uid'] and info.st_nlink==1 and
                             stat.S_IMODE(info.st_mode) in (0o400,0o600) and info.st_size<65536,
                             'unexpected native identity publication authority')
                # Qualified native TLS/BLS writers chmod ReadOnly (0400) only
                # after writing/closing bytes. Do not seal a transient empty or
                # partially written 0600 file during initial process startup.
                if stat.S_IMODE(info.st_mode)!=0o400 or info.st_size==0:complete=False
            if not complete:time.sleep(1);continue
            values=self.identity_bytes(record)
            self.write('/etc/avalanchego/identity.json',{'contract':expected,'hashes':self.digests(values)})
            self.remove('/etc/avalanchego/generation-started');return
        raise ValueError('Avalanche identity generation remains incomplete')

    def drain(self,expected,record=None):
        self.contract(expected,initial=True)
        failures=[]
        # Read protected retained authority without requiring writable storage;
        # only private grants/startup require a fresh durability barrier.
        record=record or self.account_record(expected,durable=False)
        for unit in UNITS:
            try:
                loaded=self.command('systemctl','show','--property=LoadState','--value',unit,check=False)
                self.require(loaded.stdout.strip() in (b'loaded',b'not-found',b'masked'),'unit state is unknown')
                if loaded.stdout.strip()==b'not-found':
                    active=self.command('systemctl','is-active',unit,check=False)
                    if active.returncode in (3,4) and active.stdout.strip() in (b'inactive',b'failed',b'unknown'):continue
                    self.require(active.returncode==0 and active.stdout.strip()==b'active','missing unit activity is ambiguous')
                recipient=self.command('systemctl','show','--property=User','--value',unit).stdout.decode().strip()
                self.require(recipient in (account.NAME,str(record['service_uid'])),'unit recipient is not the original Avalanche owner')
                pid=self.command('systemctl','show','--property=MainPID','--value',unit).stdout.decode().strip()
                self.require(pid.isdecimal(),'original service process could not be identified')
                if pid!='0':
                    info=self.path('/proc/'+pid).lstat()
                    self.require(stat.S_ISDIR(info.st_mode) and info.st_uid==record['service_uid'],
                                 'refusing to stop a process belonging to another numeric owner')
            except Exception:
                failures.append('unit authority');continue
            for operation in ('stop','disable'):
                try:self.command('systemctl',operation,unit)
                except Exception:failures.append(operation)
        try:
            record=record or self.account_record(expected)
            self.quiet_uid(record['service_uid'])
        except Exception:failures.append('process authority')
        self.require(not failures,'Avalanche shutdown cannot be proven; identity, data and filtering retained')

    def cancel(self,expected,reason):
        self.contract(expected,initial=True);failed=False
        try:self.write('/etc/avalanchego/stopped',{'contract':expected,'reason':reason})
        except Exception:failed=True
        try:
            phase='prepared';previous={}
            if self.path('/etc/avalanchego/lifecycle.json').exists():
                previous=json.loads(self.protected('/etc/avalanchego/lifecycle.json').read_text())
                self.require(previous.get('contract')==expected,'cancellation scope changed')
                phase=previous.get('phase','prepared')
            if reason=='destroy':phase='retired'
            self.write('/etc/avalanchego/lifecycle.json',dict(previous,contract=expected,phase=phase,intent=None))
        except Exception:failed=True
        try:self.drain(expected)
        except Exception:failed=True
        self.require(not failed,'Avalanche cancellation or shutdown failed; retained data and ingress policy')

    def restore(self,expected,envelope):
        record=self.account(expected);original=self.receipt(expected)
        self.require(set(envelope)=={'expected_hashes','bundle'} and envelope['expected_hashes']==original,
                     'restore inventory differs from original Avalanche identity')
        bundle=envelope['bundle']
        self.require(set(bundle)=={'hashes','files'} and bundle['hashes']==original and set(bundle['files'])==set(NAMES),
                     'invalid Avalanche original backup')
        values={name:base64.b64decode(value,validate=True) for name,value in bundle['files'].items()}
        self.require(all(0<len(value)<65536 for value in values.values()) and self.digests(values)==original,
                     'Avalanche backup differs from original identity')
        # Scope and original principal precede every private file write. A
        # current name resolving to another UID cannot receive restored bytes.
        self.cancel(expected,'identity-recovery');self.quiet_uid(record['service_uid'])
        current=self.identity_bytes(record,False)
        self.require(all(current[name]==values[name] for name in current),'refusing a different existing Avalanche identity')
        directory=self.staking(record)
        for name,value in values.items():
            if name in current:continue
            temporary=directory/(name+'.restore')
            if temporary.exists() or temporary.is_symlink():
                fd=os.open(temporary,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
                with os.fdopen(fd,'rb') as staged:
                    info=os.fstat(staged.fileno())
                    self.require(stat.S_ISREG(info.st_mode) and info.st_uid in (self.owner,record['service_uid']) and info.st_nlink==1 and
                                 not info.st_mode&0o077 and staged.read(65536)==value,'unexpected Avalanche restore staging file')
                    os.fchown(staged.fileno(),record['service_uid'],record['service_gid'])
                    os.fsync(staged.fileno())
                os.replace(temporary,directory/name);self.sync(directory);continue
            fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'wb') as stream:
                stream.write(value);os.fchown(stream.fileno(),record['service_uid'],record['service_gid'])
                stream.flush();os.fsync(stream.fileno())
            os.replace(temporary,directory/name);self.sync(directory)
        self.verify_identity(expected)
        return {'identity_restored':True,'service':'stopped'}

    def migrate(self,expected,expected_hashes):
        self.contract(expected)
        if expected_hashes:
            self.require(isinstance(expected_hashes,dict) and set(expected_hashes)==set(NAMES) and
                         all(isinstance(value,str) and re.fullmatch('[a-f0-9]{64}',value) for value in expected_hashes.values()),
                         'legacy migration needs complete pinned original digests')
        previous=json.loads(self.protected('/etc/avalanchego/contract.json').read_text())
        if previous.get('original_account') is not None:
            record=self.account_record(expected)
            original=record.get('migrated_identity',{})
            self.require(original==expected_hashes,'migration retry differs from original identity reservation')
            if original and not self.path('/etc/avalanchego/identity.json').exists():
                self.require(all(original[name]==digest for name,digest in self.digests(self.identity_bytes(record,False)).items()),'migration identity bytes changed')
                self.write('/etc/avalanchego/identity.json',{'contract':expected,'hashes':original})
            return self.prepare(expected)
        self.require(previous=={k:v for k,v in expected.items() if k!='owner'},'only the exact legacy Avalanche scope can be migrated')
        user=account.lookup(account.pwd.getpwnam,account.NAME)
        group=account.lookup(account.grp.getgrnam,account.NAME)
        self.require(user is not None and group is not None,'legacy Avalanche account is unavailable')
        self.require(user.pw_dir in ('/var/lib/avalanchego','/home/avalanchego','/nonexistent'),
                     'legacy Avalanche home requires explicit operator repair')
        record={'contract':expected,'protocol':2,'service_uid':user.pw_uid,'service_gid':group.gr_gid,
                'service_home':user.pw_dir,'account_established':True,'home_established':True,'migrated_identity':expected_hashes}
        account.verify(self,record);self.data_home(record);self.staking(record)
        values=self.identity_bytes(record,False)
        if expected_hashes:
            self.require(all(expected_hashes[name]==digest for name,digest in self.digests(values).items()),
                         'legacy Avalanche bytes differ from pinned inventory identity')
            legacy=self.path('/var/lib/avalanchego/staking/identity.json')
            info=legacy.lstat()
            self.require(stat.S_ISREG(info.st_mode) and info.st_uid==record['service_uid'] and info.st_nlink==1 and
                         not info.st_mode&0o077 and json.loads(legacy.read_text())==expected_hashes,
                         'legacy Avalanche manifest is not its original pinned custody')
        else:
            self.require(not values and not self.path('/var/lib/avalanchego/db').exists() and
                         not any(self.staking(record).iterdir()),'unrecorded legacy Avalanche custody cannot be adopted')
        self.drain(expected,record=record)
        self.write('/etc/avalanchego/stopped',{'contract':expected,'reason':'explicit-account-migration'})
        self.write('/etc/avalanchego/lifecycle.json',{'contract':expected,'phase':'stopped','intent':None})
        # The first atomic protocol receipt preserves the observed, explicitly
        # authorized account even if the secondary receipt write is interrupted.
        self.write('/etc/avalanchego/contract.json',dict(expected,authority_protocol=2,original_account=record),mode=0o644)
        self.save(record)
        if expected_hashes:self.write('/etc/avalanchego/identity.json',{'contract':expected,'hashes':expected_hashes})
        return {'uid':record['service_uid'],'gid':record['service_gid'],'redeploy_required':True}

    def target(self,target):
        self.require(isinstance(target,dict) and set(target)=={'version','commit','archive_sha256'} and
                     isinstance(target['version'],str) and re.fullmatch(r'v1[.]15[.](?:[2-9]|[1-9][0-9]{1,4})',target['version']) and
                     isinstance(target['commit'],str) and re.fullmatch('[a-f0-9]{40}',target['commit']) and
                     isinstance(target['archive_sha256'],str) and re.fullmatch('[a-f0-9]{64}',target['archive_sha256']),
                     'unqualified Avalanche target')
        return int(target['version'].split('.')[-1])

    def floor(self,expected,target):
        patch=self.target(target)
        path=self.protected('/etc/avalanchego/database-floor.json',missing=True)
        if path.exists():
            floor=self.durable_json('/etc/avalanchego/database-floor.json')
            self.require(floor.get('contract')==expected,'Avalanche database floor belongs to another owner')
            minimum=self.target(floor['target'])
            self.require(patch>=minimum and (patch!=minimum or target==floor['target']),
                         'Avalanche database downgrade or mutated release is refused')
        pointer=self.path('/opt/avalanchego/current')
        if pointer.exists() or pointer.is_symlink():
            link=pointer.lstat();name=os.readlink(pointer)
            self.require(stat.S_ISLNK(link.st_mode) and link.st_uid==self.owner and
                         re.fullmatch(r'/opt/avalanchego/v1[.]15[.][0-9]+',name),'native release pointer changed')
            self.require(patch>=int(name.split('.')[-1]),'remote native release is newer than the requested target')
            if name.endswith('/'+target['version']):
                self.require(self.protected(name+'/.verified-sha256').read_text().strip()==target['archive_sha256'],
                             'same-version archive differs from the retained release')

    def intended(self,expected,intent):
        self.contract(expected)
        self.require(isinstance(intent,str) and re.fullmatch('[a-f0-9]{32}',intent),'invalid Avalanche deployment intent')
        state=self.durable_json('/etc/avalanchego/lifecycle.json')
        self.require(state.get('contract')==expected and state.get('intent')==intent and state.get('phase') in ('preparing','installed') and
                     not self.path('/etc/avalanchego/stopped').exists(),'Avalanche deployment was canceled or superseded')
        return state

    def begin(self,expected,intent,target):
        self.account(expected)
        self.floor(expected,target)
        self.require(isinstance(intent,str) and re.fullmatch('[a-f0-9]{32}',intent),'invalid Avalanche deployment intent')
        # Publish the new intent while cancellation still blocks old phases.
        # A persistent I/O failure nevertheless attempts to quiesce the owner.
        failed=False
        try:self.write('/etc/avalanchego/stopped',{'contract':expected,'reason':'deployment'})
        except Exception:failed=True
        try:self.write('/etc/avalanchego/lifecycle.json',{'contract':expected,'phase':'preparing','intent':intent,'target':target})
        except Exception:failed=True
        try:self.drain(expected)
        except Exception:failed=True
        self.require(not failed,'Avalanche preparation or shutdown failed')
        self.remove('/etc/avalanchego/stopped')

    def capacity(self,expected):
        record=self.account(expected)
        loader=importlib.machinery.SourceFileLoader('avax_capacity',str(pathlib.Path(__file__).with_name('capacity.py')))
        spec=importlib.util.spec_from_loader(loader.name,loader);module=importlib.util.module_from_spec(spec);loader.exec_module(module)
        module.inspect(self.path('/var/lib/avalanchego'),expected['type'],expected['network'],record['service_uid'],self.path('/proc/self/mountinfo'))

    def purge_guard(self,expected):
        record=self.account(expected);self.quiet_uid(record['service_uid'])
        loader=importlib.machinery.SourceFileLoader('avax_purge_capacity',str(pathlib.Path(__file__).with_name('capacity.py')))
        spec=importlib.util.spec_from_loader(loader.name,loader);module=importlib.util.module_from_spec(spec);loader.exec_module(module)
        home=self.path('/var/lib/avalanchego');device=home.lstat().st_dev
        module.allocation(home,expected['network'],record['service_uid'],self.path('/proc/self/mountinfo'))
        db=home/'db'
        if db.exists():self.require(all(path.name==expected['network'] for path in db.iterdir()),'foreign database namespace retained')
        logs=home/'logs';pending=[logs] if logs.exists() or logs.is_symlink() else [];count=0
        while pending:
            path=pending.pop();info=path.lstat();count+=1
            self.require(count<=1000000 and info.st_dev==device and info.st_uid==record['service_uid'],
                         'log ownership or filesystem changed; data retained')
            if stat.S_ISDIR(info.st_mode):pending.extend(path.iterdir())
            else:self.require(stat.S_ISREG(info.st_mode),'log links or special files retained')

    def lifecycle_ready(self,expected,capacity=True):
        self.contract(expected)
        self.require(not self.path('/etc/avalanchego/stopped').exists(),'Avalanche startup is canceled')
        state=self.durable_json('/etc/avalanchego/lifecycle.json')
        self.require(state.get('contract')==expected and state.get('phase')=='installed','Avalanche installation remains incomplete')
        self.native(expected)
        if capacity:self.capacity(expected)
        self.firewall().dispatch('guard')

    def firewall(self):
        path=self.protected('/usr/local/lib/erpc/rpc-firewall.py')
        # Standard-library-only common helper; do not recursively inspect its
        # unrelated sibling namespaces/current pointers.
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as stream:
            info=os.fstat(stream.fileno())
            self.require(stat.S_ISREG(info.st_mode) and info.st_uid==self.owner and not info.st_mode&0o022 and
                         info.st_nlink==1 and 0<info.st_size<=1048576,'common firewall code is unsafe')
            raw=stream.read(1048577)
            self.require(len(raw)==info.st_size,'common firewall code changed while read')
        module={'__file__':str(path),'__name__':'avax_checked_firewall'}
        exec(compile(raw,str(path),'exec'),module)
        return module['Firewall']('avax',root=self.root,run=self.run)

    def package_guard(self,expected):
        self.account(expected)
        path=self.path('/etc/systemd/system/nginx.service')
        if path.exists() or path.is_symlink():
            info=path.lstat()
            self.require(stat.S_ISLNK(info.st_mode) and info.st_uid==self.owner and os.readlink(path)=='/dev/null',
                         'an existing nginx unit override cannot be adopted')
        result=self.command('systemctl','is-active','nginx.service',check=False)
        self.require(result.returncode in (3,4) and result.stdout.strip() in (b'inactive',b'failed',b'unknown'),
                     'an existing nginx service must be stopped by its owner before Avalanche setup')

    def publication(self,expected):
        self.account(expected);source=pathlib.Path(__file__).absolute().parent
        self.require(self.protected('/usr/local/lib/erpc/rpc-firewall.py').read_bytes()==(source.parent/'rpc-firewall.py').read_bytes(),
                     'common firewall differs from sealed carried source')
        for name in ('control.py','account.py','capacity.py','observe.py'):
            self.require(self.protected('/usr/local/lib/erpc/avax/'+name).read_bytes()==(source/name).read_bytes(),
                         'installed Avalanche helper differs from sealed carried source')
        # Obsolete public code is retired only after all new entrypoints match.
        for name in ('avax-identity.py','avax-firewall.py'):
            self.remove('/usr/local/lib/erpc/'+name)

    def native(self,expected,publish=False,target=None):
        target_pin=target
        pointer=self.path('/opt/avalanchego/current');info=pointer.lstat()
        self.require(stat.S_ISLNK(info.st_mode) and info.st_uid==self.owner,'native release pointer changed')
        target=os.readlink(pointer)
        self.require(re.fullmatch(r'/opt/avalanchego/v1[.]15[.][0-9]+',target) is not None,'unqualified Avalanche release target')
        directory=target
        target=target_pin if publish else self.durable_json('/etc/avalanchego/native.json')['target']
        self.floor(expected,target)
        self.require(directory=='/opt/avalanchego/'+target['version'],'installed release differs from caller target')
        binary=self.protected(directory+'/avalanchego');digest=hashlib.sha256(binary.read_bytes()).hexdigest()
        self.require(self.protected(directory+'/.verified-binary-sha256').read_text().strip()==digest,
                     'native binary differs from authenticated extraction')
        receipt={'contract':expected,'target':target,'binary':directory+'/avalanchego','sha256':digest,
                 'config':hashlib.sha256(self.protected('/etc/avalanchego/node.json').read_bytes()).hexdigest()}
        if publish:self.write('/etc/avalanchego/native.json',receipt)
        else:self.require(self.durable_json('/etc/avalanchego/native.json')==receipt,'native release/configuration changed')
        return binary

    def gateway(self,expected,publish=False):
        binary=self.protected('/usr/sbin/nginx')
        config=self.protected('/etc/avalanchego/proxy.conf')
        text=config.read_text()
        bindings=re.findall(r'^\s*listen (127[.]0[.]0[.]1|0[.]0[.]0[.]0):(9652|9653);$',text,re.MULTILINE)
        self.require(len(bindings)==2 and {port for address,port in bindings}=={'9652','9653'},
                     'gateway configuration has unexpected listeners')
        ports={port:address for address,port in bindings}
        receipt={'contract':expected,'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),
                 'config_sha256':hashlib.sha256(config.read_bytes()).hexdigest(),
                 'rpc_bind':ports['9652'],'metrics_bind':ports['9653']}
        if publish:self.write('/etc/avalanchego/gateway.json',receipt)
        else:self.require(self.durable_json('/etc/avalanchego/gateway.json')==receipt,
                          'gateway package or configuration changed; redeploy to requalify it')
        return receipt

    def installed(self,expected,intent):
        state=self.intended(expected,intent);self.account(expected)
        self.quiet_uid(self.account_record(expected)['service_uid'])
        self.native(expected,publish=True,target=state['target'])
        self.gateway(expected,publish=True)
        state['phase']='installed';self.write('/etc/avalanchego/lifecycle.json',state)

    @staticmethod
    def observer():
        loader=importlib.machinery.SourceFileLoader('avax_public_observer',str(pathlib.Path(__file__).with_name('observe.py')))
        spec=importlib.util.spec_from_loader(loader.name,loader);module=importlib.util.module_from_spec(spec);loader.exec_module(module)
        return module

    def wait_native(self,expected):
        for _ in range(120):
            try:self.observer().process(self,expected);return
            except Exception:time.sleep(1)
        raise ValueError('original native RPC listener is not ready; observe and retry start')

    def start_units(self,expected):
        unit='avalanchego.service'
        self.command('systemctl','enable',unit);self.command('systemctl','start',unit)
        self.require(self.command('systemctl','show','--property=Result','--value',unit).stdout.decode().strip()=='success',
                     'native service did not complete startup conditions')
        self.wait_native(expected)
        self.startup(expected,'gateway')
        unit='avalanche-rpc.service'
        self.command('systemctl','enable',unit);self.command('systemctl','start',unit)
        self.require(self.command('systemctl','show','--property=Result','--value',unit).stdout.decode().strip()=='success',
                     'gateway did not complete startup conditions')

    def startup(self,expected,component):
        self.require(component in ('native','gateway'),'unknown Avalanche service component')
        record=self.account(expected);self.lifecycle_ready(expected,capacity=component=='native')
        unit='avalanchego.service' if component=='native' else 'avalanche-rpc.service'
        for key,value in (('User',str(record['service_uid'])),('Group',str(record['service_gid'])),('SupplementaryGroups','')):
            self.require(self.command('systemctl','show','--property='+key,'--value',unit).stdout.decode().strip()==value,
                         'loaded Avalanche recipient differs from original account')
        # Native startup has no supported out-of-band instance sharing this UID.
        # Gateway prestart runs alongside the already started native unit.
        if component=='native':
            self.quiet_uid(record['service_uid'])
            target=self.durable_json('/etc/avalanchego/native.json')['target']
            self.floor(expected,target)
            self.write('/etc/avalanchego/database-floor.json',{'contract':expected,'target':target})
        else:
            self.gateway(expected)
            self.observer().process(self,expected)

    def service(self,expected,action):
        if action in ('stop','destroy'):
            self.cancel(expected,action);return {'state':'stopped','identity_and_data_preserved':True}
        self.require(action in ('start','restart'),'unsupported Avalanche service action')
        if action=='start':
            try:
                self.lifecycle_ready(expected,capacity=False)
                self.observer().process(self,expected);self.verify_identity(expected)
            except Exception:pass
            else:
                state=self.durable_json('/etc/avalanchego/lifecycle.json');state['intent']=None
                self.write('/etc/avalanchego/lifecycle.json',state)
                self.floor(expected,state['target'])
                self.write('/etc/avalanchego/database-floor.json',{'contract':expected,'target':state['target']})
                self.start_units(expected)
                return {'startup_requested':True,'original_native_process_preserved':True,'readiness':'observe separately'}
        self.cancel(expected,action)
        self.account(expected)
        state=self.durable_json('/etc/avalanchego/lifecycle.json')
        self.require(state.get('contract')==expected and state.get('phase')=='installed','redeploy incomplete Avalanche installation')
        # Cancel any queued old deployment before clearing the explicit stop.
        state['intent']=None;self.write('/etc/avalanchego/lifecycle.json',state)
        self.floor(expected,state['target'])
        self.write('/etc/avalanchego/database-floor.json',{'contract':expected,'target':state['target']})
        self.remove('/etc/avalanchego/stopped');self.lifecycle_ready(expected)
        self.start_units(expected)
        return {'startup_requested':True,'readiness':'observe separately'}

    def activate(self,expected,intent):
        state=self.intended(expected,intent)
        self.require(state['phase']=='installed','Avalanche deployment is incomplete')
        self.account(expected);self.lifecycle_ready(expected)
        self.floor(expected,state['target'])
        self.write('/etc/avalanchego/database-floor.json',{'contract':expected,'target':state['target']})
        self.start_units(expected)
        return {'startup_requested':True,'readiness':'observe separately'}

    def dispatch(self,request):
        action=request['action'];expected=request['contract']
        if action=='check-initial':self.contract(expected,initial=True);return {}
        self.contract(expected,initial=action in ('prepare','stop','destroy'))
        if action=='check':return {}
        if action=='purge-guard':self.purge_guard(expected);return {}
        if action=='prepare':return self.prepare(expected)
        if action=='migrate':return self.migrate(expected,request.get('expected_hashes',{}))
        if action=='account':
            record=self.account(expected);return {'uid':record['service_uid'],'gid':record['service_gid']}
        if action=='publication':self.publication(expected);return {}
        if action=='package-guard':self.package_guard(expected);return {}
        if action=='begin':self.begin(expected,request['intent'],request['target']);return {}
        if action=='phase':self.intended(expected,request['intent']);return {}
        if action=='deploy-check':
            self.intended(expected,request['intent']);self.account(expected)
            self.firewall().dispatch('require-confirmed',request['run'],request['bundle']);return {}
        if action=='installed':self.installed(expected,request['intent']);return {}
        if action=='activate':return self.activate(expected,request['intent'])
        if action=='authorize':self.authorize(expected);return {}
        if action=='native-condition':self.startup(expected,'native');return {}
        if action=='gateway-condition':self.startup(expected,'gateway');return {}
        if action=='native-guard':self.startup(expected,'native');self.generation_guard(expected);return {}
        if action=='gateway-guard':self.startup(expected,'gateway');return {}
        if action=='seal':self.seal(expected);return {}
        if action in ('start','stop','restart','destroy'):return self.service(expected,action)
        if action=='restore':return self.restore(expected,request['envelope'])
        if action=='status':
            result=self.observer().observe(self,expected)
            path=self.protected('/etc/avalanchego/lifecycle.json',missing=True)
            if path.exists():
                state=json.loads(path.read_text());self.require(state.get('contract')==expected,'lifecycle owner differs')
                result['lifecycle']={'phase':state.get('phase'),'desired_release':state.get('target'),
                                     'startup_canceled':self.path('/etc/avalanchego/stopped').exists()}
            return result
        if action in ('hashes','backup'):
            values=self.verify_identity(expected)
            return self.digests(values) if action=='hashes' else {'hashes':self.digests(values),'files':{
                name:base64.b64encode(value).decode() for name,value in values.items()}}
        if action=='firewall-load':self.firewall().dispatch('load');return {}
        if action=='confirm':
            fd=os.open(self.path('/opt/erpc'),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:
                fcntl.flock(fd,fcntl.LOCK_EX)
                self.intended(expected,request['intent'])
                self.firewall().confirm(request['run'],request['bundle'])
            finally:os.close(fd)
            return {}
        raise ValueError('unsupported Avalanche operation')


def main():
    resource.setrlimit(resource.RLIMIT_CORE,(0,0));os.umask(0o077)
    if os.geteuid()!=0:raise ValueError('root is required')
    control=Control()
    if len(sys.argv) in (2,5):
        action=sys.argv[1]
        raw=control.durable_json('/etc/avalanchego/contract.json',resync=action not in ('stop','destroy'))
        expected={key:raw[key] for key in ('network','type','validator','owner')}
        request={'action':action,'contract':expected}
        if action=='restore':
            payload=sys.stdin.buffer.read(262145)
            if len(payload)>262144:raise ValueError('oversized identity bundle')
            request['envelope']=json.loads(payload)
        if action=='confirm':request.update(run=sys.argv[2],bundle=sys.argv[3],intent=sys.argv[4])
    else:
        raw=sys.stdin.buffer.read(1048577)
        if len(raw)>1048576:raise ValueError('oversized Avalanche request')
        request=json.loads(raw)
    # Read-only service guards run inside a manager operation that may own the
    # global lock. Boot load and confirmation delegate locking to the common
    # firewall helper; do not take that same lock twice.
    unlocked={'native-condition','gateway-condition','native-guard','gateway-guard','seal','firewall-load','confirm','status'}
    carried=pathlib.Path(__file__).parent!=pathlib.Path('/usr/local/lib/erpc/avax')
    if carried or request['action'] in unlocked:
        result=control.dispatch(request)
    else:
        control.namespaces()
        fd=os.open(control.path('/opt/erpc'),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX);result=control.dispatch(request)
        finally:os.close(fd)
    print(json.dumps(result,separators=(',',':')))


if __name__=='__main__':
    try:main()
    except Exception:
        print('Avalanche operation refused; retained identity and private diagnostics were not emitted',file=sys.stderr)
        sys.exit(255 if sys.argv[1:] in (['native-condition'],['gateway-condition'],['native-guard'],['gateway-guard']) else 1)
