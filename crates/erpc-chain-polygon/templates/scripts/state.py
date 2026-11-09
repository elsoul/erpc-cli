# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Immutable ownership, paired release targets, capacity and service fences."""
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import stat
import uuid
import host
import accounts
import volume

ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/root','LANG':'C.UTF-8'}

SERVICES=('polygon-bor.service','polygon-heimdall.service','polygon-l1-proxy.service')
VALIDATOR_SERVICES=('polygon-peer-bor.timer','polygon-peer-heimdall.timer',
    'polygon-peer-bor.service','polygon-peer-heimdall.service',*SERVICES,'polygon-broker.service')


def unique(items):
    value={}
    for key,item in items:
        if key in value:raise ValueError('duplicate public JSON field')
        value[key]=item
    return value


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()


def profile_digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def contract(network,owner,architecture,bor_genesis,heimdall_genesis,role='fullnode',signer=None,stake_owner=None):
    if network not in ('mainnet','amoy') or architecture not in ('x86_64','aarch64'):
        raise ValueError('unsupported Polygon profile')
    if not re.fullmatch('[a-z0-9]{26}',owner) or not re.fullmatch('0x[a-f0-9]{64}',bor_genesis) or not re.fullmatch('[a-f0-9]{64}',heimdall_genesis):
        raise ValueError('invalid inventory owner or genesis identity')
    value=dict(network=network,owner=owner,architecture=architecture,bor_genesis=bor_genesis,heimdall_genesis=heimdall_genesis,role=role)
    if role=='validator':
        from signer import address
        signer,stake_owner=address(signer),address(stake_owner)
        if signer==stake_owner:raise ValueError('validator hot signer must differ from the external stake owner')
        value.update(signer=signer,stake_owner=stake_owner)
    elif role!='fullnode' or signer is not None or stake_owner is not None:
        raise ValueError('unsupported Polygon role or financial identity')
    return value


def version(tag):
    match=re.fullmatch(r'v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)',tag)
    if not match:raise ValueError('unknown native release ordering requires reviewed migration')
    return tuple(int(part) for part in match.groups())


def target(expected,profile):
    network=expected['network']
    if expected['role']=='validator':
        value=profile.get('validator')
        if (not isinstance(value,dict) or set(value)!={'phase','signer','sentries'}
                or value['signer']!=expected['signer'] or value['phase'] not in ('observing','active')
                or not isinstance(value['sentries'],list) or not 1<=len(value['sentries'])<=8):
            raise ValueError('validator release target lacks its exact original signer, phase and sentry policy')
    elif 'validator' in profile:
        raise ValueError('RPC ownership cannot select a validator runtime target')
    if (profile.get('network')!=network or profile.get('bor_genesis_hash')!=expected['bor_genesis']
            or profile.get('heimdall_genesis',{}).get('sha256')!=expected['heimdall_genesis']
            or profile.get('chain_id')!=(137 if network=='mainnet' else 80002)
            or profile.get('heimdall_chain_id')!=('heimdallv2-137' if network=='mainnet' else 'heimdallv2-80002')
            or profile.get('parent')!=('mainnet' if network=='mainnet' else 'sepolia')):
        raise ValueError('release profile differs from immutable network ownership')
    if set(profile.get('releases',{}))!={'bor','heimdall'}:
        raise ValueError('both independently reviewed client targets are required')
    generation=profile.get('genesis_generation','')
    if not isinstance(generation,str) or not generation.isdigit() or profile['heimdall_genesis']['url']!='https://storage.googleapis.com/'+network+'-heimdallv2-genesis/migrated_dump-genesis.json?generation='+generation:
        raise ValueError('genesis must use the reviewed official immutable object')
    for name,release in profile['releases'].items():
        version(release['tag'])
        repo='bor' if name=='bor' else 'heimdall-v2'
        identity='https://github.com/0xPolygon/'+repo+'/.github/workflows/packager_deb.yml@refs/tags/'+release['tag']
        if release.get('certificate_identity')!=identity:
            raise ValueError('release signature identity differs from its native source and tag')
        if not re.fullmatch('[a-f0-9]{40}',release['commit']) or expected['architecture'] not in release['assets']:
            raise ValueError('incomplete native release identity')
        package=release['assets'][expected['architecture']]
        if set(package)!={'package','signature','certificate'}:
            raise ValueError('all native package verification material is required')
        arch='amd64' if expected['architecture']=='x86_64' else 'arm64'
        base='https://github.com/0xPolygon/'+repo+'/releases/download/'+release['tag']+'/'+name+'-'+release['tag']+'-'+arch+'.deb'
        for component,suffix in [('package',''),('signature','.sig'),('certificate','.pem')]:
            pin=package[component]
            if (pin['url']!=base+suffix or not re.fullmatch('[a-f0-9]{64}',pin['sha256'])
                    or type(pin['bytes']) is not int or pin['bytes']<=0):
                raise ValueError('invalid native artifact source or pin')
    return profile


def executable(expected,profile):
    """The public Karwar catalog is executable; older records stay readable.

    Historical targets must remain parseable for stopped upgrades, independent
    monotonic source floors and retained active signing authority.
    """
    target(expected,profile)
    wanted={'bor':('v2.10.3','a16f123d9b4f41a552a3a98d93a0340430838576'),
            'heimdall':('v0.13.2','03090c94e7eaef344cd16efd6c968431c4041847')}
    if any((profile['releases'][name]['tag'],profile['releases'][name]['commit'])!=pin for name,pin in wanted.items()):
        raise ValueError('native target is outside the reviewed Karwar catalog; use explicit update')
    return profile


def monotonic(expected,old,new):
    target(expected,old);target(expected,new)
    if expected['role']=='validator' and old['validator']['phase']=='active' and new['validator']['phase']!='active':
        raise ValueError('active validator signing history cannot return to an observer identity')
    for name in ('bor','heimdall'):
        before,after=old['releases'][name],new['releases'][name]
        older,newer=version(before['tag']),version(after['tag'])
        if newer<older or (newer==older and before!=after):
            raise ValueError('downgrade or ambiguous same-version artifact change refused')


class State:
    def __init__(self,root=Path('/'),run=subprocess.run,firewall=None,usage=None,owner=0,proof=None,account=None):
        self.root,self.run,self.firewall_factory,self.usage,self.owner=root,run,firewall,usage,owner
        self.proof=host.Proof(self) if proof is None else proof
        self.accounts=accounts.Accounts(self) if account is None else account

    def path(self,path):return self.root/path.lstrip('/')

    def protected(self,path,missing=False):
        if not path.startswith('/') or any(part in ('.','..') for part in Path(path).parts):
            raise ValueError('protected host path must be absolute without traversal')
        current=self.root
        parts=Path(path).parts[1:]
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
                raise ValueError('protected host path ownership or type is unsafe')
        return current

    def namespaces(self):
        directories=('/etc/polygon','/etc/erpc/polygon','/etc/credstore.encrypted/polygon',
            '/opt/polygon','/usr/local/lib/erpc/polygon/releases')
        units=(*VALIDATOR_SERVICES,'erpc-polygon-firewall.service')
        for name in (*directories,*('/etc/systemd/system/'+unit+'.d' for unit in units)):
            directory=self.protected(name,missing=True)
            if directory.exists() and not directory.is_dir():raise ValueError('privileged namespace is not a directory')
            if directory.exists():
                for root,children,files in os.walk(directory,followlinks=False):
                    for child in (*children,*files):self.protected('/'+str((Path(root)/child).relative_to(self.root)))
        for name in ('/usr/local/lib/erpc/rpc-firewall.py',*('/etc/systemd/system/'+unit for unit in units)):
            self.protected(name,missing=True)
        parent=self.protected('/usr/local/lib/erpc/polygon',missing=True)
        for name in ('current','current.pending'):
            pointer=parent/name
            if not pointer.exists() and not pointer.is_symlink():continue
            info=pointer.lstat()
            if not stat.S_ISLNK(info.st_mode) or info.st_uid!=self.owner:raise ValueError('helper release pointer is unsafe')
            selected=os.readlink(pointer)
            if not re.fullmatch('/usr/local/lib/erpc/polygon/releases/[a-f0-9]{64}',selected):
                raise ValueError('helper pointer must select one immutable release')
            self.protected(selected)
        self.protected('/var/lib/polygon',missing=True)

    def read(self,path):return json.loads(self.protected(path).read_text(),object_pairs_hook=unique)

    def write(self,path,value,mode=0o600):
        final=self.protected(path,missing=True);pending=final.with_suffix('.pending')
        self.protected('/'+str(pending.relative_to(self.root)),missing=True)
        fd=os.open(pending,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,mode)
        with os.fdopen(fd,'wb') as stream:
            os.fchmod(stream.fileno(),mode)
            stream.write(canonical(value));stream.flush();os.fsync(stream.fileno())
        host.publish(pending,final,stop=self.root)

    def command(self,*args,check=True,**kwargs):
        kwargs.setdefault('env',ENV)
        return self.run(list(args),check=check,stdout=subprocess.PIPE,stderr=subprocess.PIPE,**kwargs)

    def ownership(self,expected,initial=False):
        saved=self.protected('/etc/polygon/contract.json',missing=True)
        if saved.is_symlink():raise ValueError('ownership cannot be a symlink')
        if not saved.exists():
            directories=[self.path(p) for p in ('/etc/polygon','/etc/erpc/polygon')]
            retained=any(p.is_symlink() or (p.exists() and any(p.iterdir())) for p in directories)
            try:volume.empty(self)
            except (ValueError,OSError):retained=True
            retained=retained or any(self.path(p).exists() or self.path(p).is_symlink() for p in
                ('/etc/credstore.encrypted/polygon','/opt/polygon/current','/usr/local/lib/erpc/polygon/current',*('/etc/systemd/system/'+unit for unit in VALIDATOR_SERVICES)))
            if not initial or retained:raise ValueError('missing ownership with retained Polygon material; implicit adoption refused')
            return
        recorded=self.read('/etc/polygon/contract.json')
        if recorded!=expected and not (isinstance(recorded,dict) and type(recorded.get('runtime_protocol')) is int and any(recorded==dict(expected,runtime_protocol=value) for value in (2,3))):
            raise ValueError('Polygon inventory owner, role, network or genesis differs')

    def runtime_owner(self,expected):
        self.ownership(expected)
        protocol=self.read('/etc/polygon/contract.json').get('runtime_protocol')
        if type(protocol) is not int or protocol!=3:
            raise ValueError('legacy runtime authority requires reviewed storage migration before account provisioning or startup')
        volume.verify(self,expected)

    def firewall(self):
        if self.firewall_factory:return self.firewall_factory()
        spec=importlib.util.spec_from_file_location('polygon_firewall',self.protected('/usr/local/lib/erpc/rpc-firewall.py'))
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        return module.Firewall('polygon',self.root,self.run)

    def resources(self,expected):
        import host_resources
        return host_resources.verify(self,expected)

    def capacity(self,expected):
        self.resources(expected)
        volume.verify(self,expected)
        root_available=None
        if self.usage:
            free,allocated=self.usage()
        else:
            data=self.path('/var/lib/polygon')
            if data.is_symlink() or not data.is_dir():raise ValueError('Polygon data volume is missing')
            device=data.stat().st_dev
            for descendant in (data/'bor',data/'bor/data',data/'heimdall',data/'heimdall/data',data/'genesis'):
                if descendant.is_symlink() or (descendant.exists() and descendant.stat().st_dev!=device):
                    raise ValueError('mount provisioned storage at /var/lib/polygon; nested mounts are unsupported')
            root_stats=os.statvfs(self.path('/opt/polygon'))
            root_available=root_stats.f_bavail*root_stats.f_frsize
            if root_available<2*1024**3:raise ValueError('Polygon requires 2 GiB operating headroom on its OS/artifact filesystem')
            stats=os.statvfs(data);free=stats.f_bavail*stats.f_frsize
            allocated=0
            for database in (data/'bor/data',data/'heimdall/data'):
                if database.exists():
                    result=self.command('du','-s','-x','--block-size=1','--exclude=lost+found',str(database),timeout=180)
                    first=result.stdout.split(maxsplit=1)[0]
                    if not first.isdigit():raise ValueError('allocated database usage is unavailable')
                    allocated+=int(first)
        floor,reserve=(5_500_000_000_000,128*1024**3) if expected['network']=='mainnet' else (1_500_000_000_000,64*1024**3)
        if type(free) is not int or type(allocated) is not int or min(free,allocated)<0 or free<reserve or free+allocated<floor:
            raise ValueError('Polygon bootstrap capacity or operating reserve is insufficient; stop/destroy remain available')
        return dict(available_bytes=free,allocated_bytes=allocated,root_available_bytes=root_available,bootstrap_capacity_bytes=floor,operating_reserve_bytes=reserve)

    def services(self):
        path=self.path('/etc/polygon/contract.json')
        if path.exists() and self.read('/etc/polygon/contract.json').get('role')=='validator':return VALIDATOR_SERVICES
        return SERVICES

    def stop(self,disable=False):
        existing=[]
        for service in self.services():
            result=self.command('systemctl','show','--property=LoadState','--value',service,check=False)
            loaded=result.stdout.decode().strip()
            if result.returncode or loaded not in ('loaded','masked','not-found'):
                raise ValueError('cannot establish managed service state')
            active=self.command('systemctl','is-active',service,check=False).stdout.decode().strip()
            pid=self.command('systemctl','show','--property=MainPID','--value',service).stdout.decode().strip()
            if loaded!='not-found' or active not in ('inactive','failed') or pid!='0':existing.append(service)
        if existing:
            self.command('systemctl',*(['disable','--now'] if disable else ['stop']),*existing)
        self.stopped()

    def stopped(self):
        for service in self.services():
            result=self.command('systemctl','show','--property=LoadState','--value',service,check=False)
            if result.returncode:raise ValueError('cannot establish service drain state')
            active=self.command('systemctl','is-active',service,check=False).stdout.decode().strip()
            pid=self.command('systemctl','show','--property=MainPID','--value',service).stdout.decode().strip()
            if active not in ('inactive','failed') or pid!='0':raise ValueError('all managed processes must finish draining')
        self.proof.quiescent();self.proof.unoccupied()

    def phase(self,expected,intent,profile=None,helpers=None):
        self.ownership(expected);volume.verify(self,expected)
        if self.path('/etc/polygon/stopped').exists():
            raise ValueError('Polygon deployment was explicitly stopped')
        record=self.read('/etc/polygon/intent.json')
        if not re.fullmatch('[a-f0-9]{32}',intent or '') or record.get('intent')!=intent:
            raise ValueError('Polygon deployment was stopped or superseded')
        if helpers is not None and record.get('helpers')!=helpers:
            raise ValueError('phase differs from the reviewed helper revision')
        wanted=target(expected,record['profile'])
        if profile is not None and target(expected,profile)!=wanted:
            raise ValueError('phase differs from the original reviewed release pair')
        executable(expected,wanted)
        return wanted

    def invalidate(self,reason):
        record=self.read('/etc/polygon/intent.json') if self.path('/etc/polygon/intent.json').exists() else {}
        record['intent']=reason+':'+uuid.uuid4().hex
        self.write('/etc/polygon/intent.json',record)

    def reserve_target(self,expected,profile,helpers,failure=None):
        """Publish only a conservative release floor, never an executable intent.

        Old carried helpers already compare this record monotonically. Keep an
        unactivated validator in observing mode until fresh admission approves
        its active transition; a failed first activation must remain recoverable.
        """
        self.ownership(expected);executable(expected,profile)
        if not re.fullmatch('[a-f0-9]{64}',helpers):raise ValueError('invalid qualified helper identity')
        previous=[]
        for name in ('installed.json','intent.json'):
            path='/etc/polygon/'+name
            if self.path(path).exists():
                saved=self.read(path).get('profile')
                if saved is not None:previous.append(target(expected,saved))
        wanted=json.loads(canonical(profile))
        if expected['role']=='validator':
            wanted['validator']['phase']='active' if any(value['validator']['phase']=='active' for value in previous) else 'observing'
        for saved in previous:monotonic(expected,saved,wanted)
        try:self.write('/etc/polygon/intent.json',{'intent':'qualified:'+uuid.uuid4().hex,'profile':wanted,'helpers':helpers})
        except Exception:
            if failure is not None:failure()
            raise
        return wanted

    def prepare(self,expected,intent,profile,helpers):
        self.ownership(expected)
        executable(expected,profile)
        if not re.fullmatch('[a-f0-9]{32}',intent) or not re.fullmatch('[a-f0-9]{64}',helpers):raise ValueError('invalid deployment intent or helper revision')
        for filename in ('installed.json','intent.json'):
            path='/etc/polygon/'+filename
            if self.path(path).exists():
                previous=self.read(path).get('profile')
                if previous is not None:monotonic(expected,previous,profile)
        self.capacity(expected)
        if (self.path('/etc/polygon/stopped').exists() and self.path('/etc/polygon/intent.json').exists()
                and self.read('/etc/polygon/intent.json').get('intent')==intent):
            raise ValueError('a cancelled preparation requires a new deployment intent')
        self.write('/etc/polygon/intent.json',{'intent':intent,'profile':profile,'helpers':helpers})
        host.fence(self.protected('/etc/polygon/preparing',missing=True),self.root)
        # An interrupted upgrade must not boot an older unit that delivered
        # credentials before its prestart guard. Only sealed activation enables
        # the checked numeric-recipient units again.
        self.stop(disable=True)
        # A new durable intent and preparation fence supersede cancellation.
        # Never let the delayed activation of the cancelled run remove it.
        host.unlink(self.protected('/etc/polygon/stopped',missing=True),self.root)

    def locked(self):
        class Lock:
            def __enter__(inner):
                inner.fd=os.open(self.path('/opt/erpc'),os.O_RDONLY)
                fcntl.flock(inner.fd,fcntl.LOCK_EX)
            def __exit__(inner,*args):os.close(inner.fd)
        return Lock()
