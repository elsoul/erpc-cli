#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Dedicated Kaia nodes: immutable roles, original custody and native shutdown."""
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import pwd
import secrets
import shutil
import stat
import subprocess
import sys
import time
from types import SimpleNamespace
import urllib.request

ROOT=Path('/var/lib/erpc-kaia')
TRUST_ANCHOR=Path('/')
MOUNTINFO=Path('/proc/self/mountinfo')
PROC=Path('/proc')
CONF=Path('/etc/erpc/kaia')
HELPERS=Path('/usr/local/lib/erpc/kaia')
LAUNCHER=Path('/usr/local/lib/erpc/kaia-control')
UNIT_DIRECTORY=Path('/etc/systemd/system')
LOCK=Path('/run/lock/erpc-kaia.lock')
OPERATION_ROOT=Path('/opt/erpc')
DOCKER=['/usr/bin/docker','--host=unix:///var/run/docker.sock']
DOCKER_SOCKET=Path('/var/run/docker.sock')
DOCKER_CONTAINERS=Path('/var/lib/docker/containers')
DOCKER_CONFIG=Path('/etc/docker/daemon.json')
DOCKER_OVERRIDES=Path('/etc/systemd/system/docker.service.d')
UNIT='erpc-kaia.service'
CONTAINER='erpc-kaia'
RESERVE=200_000_000_000
ROOT_UID=0
CORE_RUNTIME=Path('/run/erpc-kaia-corecell')
HELPER_PROFILE=('control.py','bootstrap.py','custody.py','corecell.py','coreaccount.py','catalog.json')

class Refused(Exception):pass

def require(value,message):
    if not value:raise Refused(message)

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

def load_dependencies():
    global bootstrap,custody,corecell,coreaccount,CATALOG
    trusted_imports(Path(__file__).parent)
    import bootstrap,custody,corecell,coreaccount
    CATALOG=json.loads((Path(__file__).parent/'catalog.json').read_text())

def environment():
    return {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8','HOME':'/root'}

def run(argv,*,input=None,allowed=(0,),timeout=120):
    result=subprocess.run(argv,input=input,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,check=False,env=environment())
    require(result.returncode in allowed,'Kaia host operation failed; inspect the owned service journal')
    return result.stdout

def network(state):return CATALOG['networks'][state['network']]

def snapshot(state):return network(state)['snapshots'][state['snapshot']]

def validate(request,release_required=True):
    require(isinstance(request,dict),'invalid Kaia request')
    require(request.get('network') in ('mainnet','kairos') and request.get('role') in ('rpc','validator'),'unsupported Kaia network/role')
    require(request.get('platform')=='amd64','only the qualified AMD64 image is supported')
    require(request.get('storage') in ('full','pruned'),'unsupported Kaia database mode')
    require(isinstance(request.get('snapshot'),str) and ((request['storage']=='full' and request['snapshot']=='genesis') or (request['storage']=='pruned' and re.fullmatch('kaia-'+request['network']+r'-pruning-chaindata-[0-9]{14}\.tar\.zst',request['snapshot']))),'invalid immutable Kaia bootstrap selection')
    require(isinstance(request.get('image'),str) and re.fullmatch(r'docker\.io/kaiachain/kaia@sha256:[a-f0-9]{64}',request['image']),'invalid bounded Kaia image target')
    require(isinstance(request.get('genesis'),str) and re.fullmatch('0x[a-f0-9]{64}',request['genesis']),'invalid immutable Kaia genesis')
    for key,pattern in (('owner','[a-z0-9]{1,80}'),('config_id','[a-f0-9]{64}'),('commit','[a-f0-9]{40}'),('version','[0-9]{1,5}\\.[0-9]{1,5}\\.[0-9]{1,5}')):
        require(isinstance(request.get(key),str) and re.fullmatch(pattern,request[key]),'invalid bounded Kaia metadata')
    if request['role']=='validator':corecell.validate(SimpleNamespace(**globals()),request)
    if release_required:
        require((request['version'],request['commit'])==(CATALOG['version'],CATALOG['commit']),'Kaia release is not in the reviewed catalog')
        require(request['image']==CATALOG['image'],'Kaia image differs from the reviewed platform digest')
        require(request['genesis']==network(request)['genesis'],'reviewed Kaia genesis differs from ownership')
        if request['storage']=='pruned':require(request['snapshot'] in network(request)['snapshots'],'original Kaia snapshot is not in this catalog')

def contract(request):
    keys=('owner','network','role','platform','storage','snapshot','genesis')
    if request['role']=='validator':keys+=('node_kind','advertise')
    return {key:request[key] for key in keys}

def target_pin(request):
    validate(request,False)
    keys=('version','commit','image','config_id')
    if request['role']=='validator':keys+=('peers','reward_address','manager_address','staking_address','gc_id')
    return {key:request[key] for key in keys}

def pin(request):
    validate(request)
    return target_pin(request)

def image(state):
    pin(state)
    return CATALOG['image']

def unit(_state=None):return UNIT

def loaded(name=UNIT):
    value=run(['systemctl','show','--property=LoadState','--value',name],allowed=(0,1)).strip()
    require(value in (b'loaded',b'not-found',b'masked'),'cannot establish service ownership')
    return value!=b'not-found'

def active(name=UNIT):
    return run(['systemctl','is-active',name],allowed=(0,3,4)).decode().strip()

def save(state):
    protected_root()
    temporary = ROOT / 'owner.new'
    require(not temporary.is_symlink(), 'unsafe ownership file')
    temporary.unlink(missing_ok=True)
    fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(state, stream)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, ROOT / 'owner.json')
    fd = os.open(ROOT, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def check_container(state):
    executable = Path(DOCKER[0])
    if not executable.is_file():
        require(not DOCKER_CONTAINERS.exists(), 'uninspected Docker state requires operator recovery')
        return
    # Resume an interrupted first apt installation before Docker was ever
    # started. A missing daemon is never treated as proof for an installed node
    # or a pre-existing/custom Docker installation.
    if state.get('phase')=='prepared' and state.get('docker_fresh_install') is True and not DOCKER_SOCKET.exists():
        require(not DOCKER_CONFIG.exists() and not DOCKER_OVERRIDES.exists(), 'new Docker configuration changed before initialization')
        require(not DOCKER_CONTAINERS.is_symlink() and (not DOCKER_CONTAINERS.exists() or (DOCKER_CONTAINERS.is_dir() and not any(DOCKER_CONTAINERS.iterdir()))),'uninspected Docker containers exist')
        return
    name = CONTAINER
    listed = run([*DOCKER, 'container', 'ls', '--all', '--format', '{{.Names}}', '--filter', 'name=^/' + name + '$']).decode().splitlines()
    if not listed:
        return
    require(listed == [name], 'unexpected Kaia container identity')
    raw = run([*DOCKER, 'container', 'inspect', name])
    require(len(raw) <= 1024 * 1024, 'oversized container inspection')
    result = json.loads(raw)
    require(isinstance(result, list) and len(result) == 1, 'ambiguous Kaia container ownership')
    labels = result[0].get('Config', {}).get('Labels', {}) or {}
    require(all(labels.get('erpc.' + key) == state[key] for key in ('owner', 'role', 'network')),
            'an unowned Kaia container exists; nothing stopped or replaced')
    return result[0]


def owned_ports(pid, ports):
    require(type(pid) is int and pid > 0, 'service process identity is unavailable')
    raw = run(['ss', '-H', '-lntp'])
    require(len(raw) <= 1024 * 1024, 'oversized local socket inspection')
    lines = raw.decode().splitlines()
    for port in ports:
        matches = [line for line in lines if len(line.split()) >= 5 and line.split()[3] == '127.0.0.1:' + str(port)]
        if len(matches) != 1 or not re.search(r'pid=' + str(pid) + r'(?:,|\))', matches[0]):
            return False
    return True


def rpc(method, params=None, port=8551):
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or []}).encode()
    request = urllib.request.Request('http://127.0.0.1:' + str(port), data=body, headers={'Content-Type': 'application/json'})
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *_args, **_kwargs):
            raise Refused('local inspection cannot redirect')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=10) as response:
        raw = response.read(1024 * 1024 + 1)
    require(len(raw) <= 1024 * 1024, 'oversized Kaia inspection response')
    value = json.loads(raw)
    require(value.get('jsonrpc') == '2.0' and value.get('id') == 1 and 'result' in value and 'error' not in value, 'RPC inspection unavailable')
    return value['result']


def protected_directory(path):
    """A writable ancestor permits replacement of even a private root-owned file."""
    require(path.is_absolute() and os.path.normpath(path) == str(path), 'invalid Kaia protected path')
    current = TRUST_ANCHOR
    for part in (None, *path.relative_to(TRUST_ANCHOR).parts):
        if part is not None: current = current / part
        try: info = current.lstat()
        except FileNotFoundError: continue
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == ROOT_UID and info.st_mode & 0o022 == 0,
                'Kaia protected paths require real root-owned nonwritable ancestors')


def protected_file(path, private=False, missing=True):
    protected_directory(path.parent)
    try: info = path.lstat()
    except FileNotFoundError:
        require(missing, 'Kaia ownership or helper is missing'); return
    require(stat.S_ISREG(info.st_mode) and info.st_uid == ROOT_UID and info.st_nlink == 1 and
            info.st_mode & (0o177 if private else 0o022) == 0,
            'unsafe Kaia owner or privileged file')
    if private: require(info.st_size <= 65536, 'oversized Kaia owner receipt')


def owned_units():
    return (UNIT, 'erpc-kaia-firewall.service')


def protected_paths():
    for path in (ROOT, ROOT / 'identity', CONF, HELPERS, UNIT_DIRECTORY): protected_directory(path)
    protected_file(LAUNCHER)
    protected_file(HELPERS.parent / 'rpc-firewall.py')
    dropins = [UNIT_DIRECTORY / (name + '.d') for name in owned_units()]
    for name in owned_units(): protected_file(UNIT_DIRECTORY / name)
    for directory in dropins:
        protected_directory(directory)
        if directory.exists():
            require(all(path.name in ('50-erpc-firewall-guard.conf', '50-erpc-firewall-guard.conf.new') for path in directory.iterdir()),
                    'unmanaged Kaia systemd drop-ins cannot change the guarded service')
    for name in ('owner.json', 'owner.new'): protected_file(ROOT / name, private=True)
    # current is the sole intentional symlink. Its closed release namespace and
    # every descendant are protected before any carried play copies into them.
    for tree in (HELPERS, CONF, *dropins):
        if not tree.exists(): continue
        pending = [tree]
        while pending:
            directory = pending.pop()
            protected_directory(directory)
            for path in directory.iterdir():
                info = path.lstat()
                if path == HELPERS / 'current':
                    require(stat.S_ISLNK(info.st_mode) and info.st_uid == ROOT_UID,
                            'unsafe Kaia current release pointer')
                    target = Path(os.readlink(path))
                    if not target.is_absolute(): target = HELPERS / target
                    require(target.parent == HELPERS / 'releases' and re.fullmatch('[a-f0-9]{64}', target.name),
                            'Kaia current pointer leaves the release namespace')
                    protected_directory(target)
                    require(target.is_dir(), 'Kaia current release is missing')
                elif stat.S_ISDIR(info.st_mode): pending.append(path)
                else: protected_file(path, missing=False)


def verify_publication():
    protected_paths()
    pointer = HELPERS / 'current'
    require(pointer.is_symlink(), 'Kaia release publication is incomplete')
    target = Path(os.readlink(pointer))
    if not target.is_absolute(): target = HELPERS / target
    digest = hashlib.sha256()
    source = Path(__file__).resolve().parent
    for name in HELPER_PROFILE:
        installed = target / name
        protected_file(installed, missing=False)
        raw = (source / name).read_bytes()
        require(installed.read_bytes() == raw, 'Kaia published helper differs from its sealed source')
        digest.update(raw)
    require(target.name == digest.hexdigest(), 'Kaia published release identity differs')
    protected_file(LAUNCHER, missing=False)
    require(LAUNCHER.read_bytes() == (source / 'launcher.py').read_bytes(), 'Kaia published launcher differs from its sealed source')
    return {'helpers': 'verified'}


def protected_root():
    protected_paths()


def single_filesystem():
    """Reject nested mounts without walking a multi-terabyte database tree."""
    with MOUNTINFO.open('rb') as source:raw=source.read(1024*1024+1)
    require(0<len(raw)<=1024*1024,'cannot establish Kaia mount topology')
    roots=[ROOT/name for name in ('data','snapshot-stage','snapshot-downloads')]
    escapes={'040':' ','011':'\t','012':'\n','134':'\\'}
    for line in raw.decode().splitlines():
        fields=line.split()
        require(len(fields)>=10 and '-' in fields[6:] and fields[4].startswith('/'),'invalid Linux mount topology')
        decoded=re.sub(r'\\(040|011|012|134)',lambda match:escapes[match[1]],fields[4])
        mount=Path(decoded)
        require(os.path.normpath(mount)==str(mount),'ambiguous Linux mount path')
        require(not any(mount==path or path in mount.parents for path in roots),
                'nested Kaia database or bootstrap mounts are unsupported')
    probe=ROOT
    while not probe.exists():probe=probe.parent
    device=probe.stat().st_dev
    for path in [*roots,ROOT/'data/klay',ROOT/'data/klay/chaindata',ROOT/'snapshot-stage/klay',ROOT/'snapshot-stage/klay/chaindata']:
        require(not path.is_symlink(),'unsafe Kaia filesystem boundary')
        if path.exists():
            require(path.is_dir() and path.stat().st_dev==device,'Kaia native database and bootstrap require one filesystem')


def state_read():
    protected_root()
    path=ROOT/'owner.json'
    require(not ROOT.is_symlink() and path.is_file() and not path.is_symlink(),'Kaia ownership missing or unsafe')
    require(path.stat().st_uid==ROOT_UID and path.stat().st_mode&0o077==0 and path.stat().st_size<=65536,'unsafe Kaia ownership permissions or size')
    state=json.loads(path.read_text());validate(state,False)
    require(state.get('phase') in ('prepared','installing','installed','retired'),'unknown Kaia ownership format')
    return state


def check(state,request):
    protected_root()
    validate(request,False)
    require(contract(state)==contract(request),'Kaia owner/network/role/platform/storage mismatch; nothing changed')
    for path in (ROOT,ROOT/'data',ROOT/'data/klay',ROOT/'data/klay/chaindata',ROOT/'identity',CONF):
        require(not path.is_symlink(),'unsafe Kaia storage/configuration')


def capacity(state,installation=False):
    single_filesystem()
    engine=DOCKER_CONTAINERS.parent
    if Path(DOCKER[0]).is_file() and DOCKER_SOCKET.exists():
        raw=run([*DOCKER,'info','--format','{{.DockerRootDir}}']).decode().strip()
        require(raw and Path(raw).is_absolute() and os.path.normpath(raw)==raw,'Docker storage location is unavailable or ambiguous')
        engine=Path(raw)
    while not engine.exists():engine=engine.parent
    require(shutil.disk_usage(engine).free>=(10 if installation else 2)*1024**3,'insufficient Docker/OS artifact headroom')
    probe=ROOT
    while not probe.exists():probe=probe.parent
    allocated=0
    for name in ('data','snapshot-stage','snapshot-downloads'):
        path=ROOT/name
        require(not path.is_symlink(),'unsafe capacity path')
        if path.exists():
            require(path.is_dir() and path.stat().st_dev==probe.stat().st_dev,'Kaia data and bootstrap require one filesystem')
            raw=run(['/usr/bin/du','-sx','-B1',str(path)]).split()
            require(raw and raw[0].isdigit(),'cannot measure allocated Kaia data')
            allocated+=int(raw[0])
    initial=4001*1024**3
    if state['storage']=='pruned':
        selected=snapshot(state)
        initial=max(initial,selected['bytes']+selected['uncompressed_bytes']+RESERVE)
    require(shutil.disk_usage(probe).free>=max(RESERVE,initial-allocated),'insufficient Kaia bootstrap capacity or operating reserve')


def prepare(request):
    protected_root()
    validate(request)
    require(not ROOT.is_symlink(),'unsafe Kaia ownership root')
    if (ROOT/'owner.json').exists():
        state=state_read();check(state,request)
        check_container(state)
        require(state['phase']=='prepared' and pin(state)==pin(request),'host already reserved; resume its deployment')
        capacity(state,installation=True);return {'phase':'prepared'}
    require(not ROOT.exists() or (ROOT.is_dir() and not any(ROOT.iterdir())),'unowned Kaia data or custody cannot be adopted')
    for path in (CONF,HELPERS,LAUNCHER,*[UNIT_DIRECTORY/name for name in owned_units()],
                 *[UNIT_DIRECTORY/(name+'.d') for name in owned_units()]):
        require(not path.exists() and not path.is_symlink(),'unowned Kaia artifacts exist')
    require(not loaded(),'unowned Kaia service exists')
    for lookup in (pwd.getpwnam,grp.getgrnam):
        try:lookup('erpc-kaia')
        except KeyError:continue
        raise Refused('unowned Kaia service account exists')
    require(check_container(request) is None,'unowned container exists')
    state=dict(contract(request),**pin(request),phase='prepared',startup_revoked=True,docker_fresh_install=not Path(DOCKER[0]).exists())
    if state['role']=='validator':state.update(coreaccount.reserve(SimpleNamespace(**globals())))
    capacity(state,installation=True);ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
    fd=os.open(ROOT.parent,os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)
    save(state)
    return {'phase':'prepared'}


def identity(state,create=False):
    if state['role']=='validator':
        require(state.get('backup_confirmed') is True,'concealed original backup must be confirmed before deployment')
        custody.read(SimpleNamespace(**globals()),state)
        return
    directory=ROOT/'identity';path=directory/'nodekey';pending=directory/'nodekey.new'
    require(not directory.is_symlink() and not path.is_symlink() and not pending.is_symlink(),'unsafe Kaia node identity')
    if 'identity_sha256' not in state:
        require(create and state['phase']=='installing','uninitialized Kaia node identity')
        require(not path.exists(),'unreceipted published node identity cannot be adopted')
        directory.mkdir(mode=0o750,exist_ok=True)
        if not pending.exists():
            order=int('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',16)
            value=0
            while not 0<value<order:value=int.from_bytes(secrets.token_bytes(32),'big')
            fd=os.open(pending,os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_WRONLY,0o600)
            with os.fdopen(fd,'w') as output:
                output.write(format(value,'064x'));output.flush();os.fsync(output.fileno())
            descriptor=os.open(directory,os.O_DIRECTORY)
            try:os.fsync(descriptor)
            finally:os.close(descriptor)
        require(pending.is_file() and pending.stat().st_uid==ROOT_UID and pending.stat().st_nlink==1 and pending.stat().st_size==64,'unsafe pending node identity')
        raw=pending.read_bytes()
        require(re.fullmatch(b'[a-f0-9]{64}',raw) and 0<int(raw,16)<int('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',16),'invalid pending node identity')
        state['identity_sha256']=hashlib.sha256(raw).hexdigest();save(state)
    if not path.exists() and pending.exists() and create:
        require(hashlib.sha256(pending.read_bytes()).hexdigest()==state['identity_sha256'],'pending identity differs from its receipt')
        os.replace(pending,path)
        descriptor=os.open(directory,os.O_DIRECTORY)
        try:os.fsync(descriptor)
        finally:os.close(descriptor)
    require(path.is_file() and path.stat().st_size==64 and path.stat().st_uid==ROOT_UID and path.stat().st_nlink==1 and hashlib.sha256(path.read_bytes()).hexdigest()==state['identity_sha256'],'established Kaia identity missing or changed')
    if create:
        os.chown(directory,0,state['service_gid']);directory.chmod(0o750)
        os.chown(path,0,state['service_gid']);path.chmod(0o440)
    require(path.stat().st_mode&0o227==0,'node identity is writable or public')


def stop_container(state):
    check(state,state)
    container=check_container(state)
    if container is None:
        account_quiet(state);return
    identity=container.get('Id');running=container.get('State',{}).get('Running')
    require(isinstance(identity,str) and re.fullmatch('[a-f0-9]{64}',identity) and type(running)is bool,'ambiguous owned container state')
    if running:
        # Docker stop sends SIGKILL after its grace period. Send only SIGTERM and
        # fail closed on timeout; never tear down a database writer forcibly.
        run([*DOCKER,'container','kill','--signal=SIGTERM',identity])
        deadline=time.monotonic()+1800
        while time.monotonic()<deadline:
            observed=check_container(state)
            if observed is None or (observed.get('Id')==identity and observed.get('State',{}).get('Running')is False):break
            require(observed.get('Id')==identity,'container changed during graceful shutdown')
            time.sleep(1)
    remaining=check_container(state)
    require(remaining is None or (remaining.get('Id')==identity and remaining.get('State',{}).get('Running')is False and remaining.get('State',{}).get('Pid')==0),'Kaia container still runs or changed during shutdown')
    if remaining is not None:
        # Remove only the stopped immutable container ID, never a volume and
        # never with --force. This also invalidates a queued Docker start of the
        # old object; a racing start/removal must fail closed on reinspection.
        run([*DOCKER,'container','rm',identity],allowed=(0,1))
        require(check_container(state) is None,'old Kaia container remains or a replacement appeared')
    account_quiet(state)


def account_quiet(state):
    """An absent Docker/service record cannot hide another dedicated-UID writer."""
    uid=state.get('service_uid')
    if uid is None:return
    require(type(uid)is int and 100<=uid<=65534,'invalid dedicated account identity')
    for entry in PROC.iterdir():
        if not entry.name.isdigit():continue
        try:info=entry.stat()
        except FileNotFoundError:continue
        require(info.st_uid!=uid,'unowned or orphan Kaia account process remains; no data mutation')


def account(state):
    if state['role']=='validator':
        require(state.get('account_established') is True,'original core-cell account setup is incomplete')
        coreaccount.verify(SimpleNamespace(**globals()),state);return
    user=pwd.getpwnam('erpc-kaia');group=grp.getgrnam('erpc-kaia')
    require((user.pw_uid,user.pw_gid,group.gr_gid)==(state.get('service_uid'),state.get('service_gid'),state.get('service_gid')),'dedicated Kaia account changed')


def stop(state):
    check_container(state)  # Refuse foreign or uninspectable containers before unit mutation.
    if loaded():
        run(['systemctl','stop',UNIT],timeout=1860)
        require(active() in ('inactive','failed','unknown'),'Kaia service did not stop')
        require(run(['systemctl','show','--property=MainPID','--value',UNIT]).strip() in (b'0',b''),'Kaia service process remains')
    stop_container(state)


def cancel_and_stop(state,retire=False):
    state.update(deploy_intent=None,deploy_target=None,startup_revoked=True)
    if retire:state['phase']='retired'
    failures=[]
    try:save(state)
    except Exception:failures.append('cancellation storage')
    try:stop(state)
    except Exception:
        failures.append('service shutdown')
        # A unit-control failure must still try the freshly inspected owned
        # immutable container ID. Foreign or ambiguous ownership never signals.
        try:stop_container(state)
        except Exception:failures.append('owned container drain')
    if failures:
        try:save(state)
        except Exception:failures.append('post-shutdown storage')
    try:
        if loaded():run(['systemctl','disable',UNIT])
    except Exception:failures.append('unit disable')
    if failures:
        raise Refused('Kaia stop encountered '+', '.join(failures)+'; owned shutdown attempted, repair storage/services and retry') from None
    return {'phase':state['phase'],'data_preserved':True}


def firewall_controller():
    import runpy
    protected_paths()
    path=HELPERS.parent/'rpc-firewall.py'
    protected_file(path,missing=False)
    return runpy.run_path(str(path),run_name='erpc_kaia_firewall')['Firewall']('kaia')


def firewall(state):
    receipt=state.get('firewall')
    require(isinstance(receipt,dict) and set(receipt)=={'run','bundle'},'confirmed firewall receipt missing')
    require(isinstance(receipt['run'],str) and re.fullmatch('[a-z0-9-]{1,80}',receipt['run']) and isinstance(receipt['bundle'],str) and re.fullmatch('[a-f0-9]{64}',receipt['bundle']),'invalid firewall receipt')
    firewall_controller().dispatch('require-confirmed',receipt['run'],receipt['bundle'])


def verify_image(state):
    result=json.loads(run([*DOCKER,'image','inspect',image(state)]))
    require(isinstance(result,list) and len(result)==1 and result[0].get('Architecture')=='amd64' and result[0].get('Os')=='linux','Kaia image platform differs')
    require(any(value.endswith('@'+image(state).split('@')[1]) for value in result[0].get('RepoDigests',[])),'Kaia image content differs')


def guard(state):
    check(state,state)
    require(state['phase']=='installed' and state.get('installed')==pin(state) and state.get('startup_revoked')is False,'Kaia installation is incomplete, retired or fenced')
    account(state);capacity(state);identity(state);firewall(state)
    if state['role']=='validator':
        require(run(['timedatectl','show','--property=NTPSynchronized','--value']).strip()==b'yes','synchronized host time is required for core-cell startup')
        path=CONF/'static-nodes.json';protected_file(path,missing=False)
        require(path.read_bytes()==corecell.configuration(SimpleNamespace(**globals()),state),'approved static peer configuration differs')
        trusted=CONF/'trusted-nodes.json';protected_file(trusted,missing=False)
        require(trusted.read_bytes()==b'[]','unreviewed trusted peer override')
    container=check_container(state)
    if container is not None and container.get('State',{}).get('Running')is True:
        require(str(container.get('Config',{}).get('Image','')).endswith('@'+state['image'].split('@')[1]),'owned running container image differs from the installed pin')
    require((ROOT/'data/klay/chaindata').is_dir(),'published Kaia bootstrap data is missing')


def arguments(state):
    common=['--'+state['network'],'--datadir=/data','--nodekey=/identity/nodekey',
            '--auction.disable','--port=32323','--multichannel=false','--syncmode=full','--gcmode=full',
            '--state.live-pruning='+str(state['storage']=='pruned').lower(),
            '--rpc','--rpcaddr=127.0.0.1','--rpcport=8551','--rpcapi=kaia,klay,eth,net,web3',
            '--rpcvhosts=localhost','--rpccorsdomain=','--ws','--wsaddr=127.0.0.1','--wsport=8552',
            '--wsapi=kaia,klay,eth,net,web3','--wsorigins=localhost','--ipcpath=/data/kaia.ipc',
            '--rpc.unsafe-debug.disable','--txpool.exec-slots.all=4096','--txpool.nonexec-slots.all=4096',
            '--txpool.exec-slots.account=4096','--txpool.nonexec-slots.account=4096']
    if state['role']=='validator':
        common+=['--bls-nodekey=/identity/bls-nodekey','--nodiscover','--nat=extip:'+state['advertise']]
        if state['node_kind']=='cn':common+=['--gasless.disable','--rewardbase='+state['reward_address']]
    return common


def execute(state):
    guard(state);verify_image(state)
    uid,gid=state.get('service_uid'),state.get('service_gid')
    require(all(type(v)is int and 100<=v<=65534 for v in (uid,gid)),'invalid Kaia service account')
    previous=check_container(state)
    if previous is not None:
        require(previous.get('State',{}).get('Running')is False,'Kaia container already runs outside its service')
        identity=previous.get('Id');require(isinstance(identity,str) and re.fullmatch('[a-f0-9]{64}',identity),'ambiguous stopped container')
        run([*DOCKER,'container','rm',identity])
    account_quiet(state)
    identity_path=ROOT/'identity';executable='ken';extra=[]
    if state['role']=='validator':
        custody.materialize(SimpleNamespace(**globals()),state,CORE_RUNTIME,gid)
        identity_path=CORE_RUNTIME;executable='kcn' if state['node_kind']=='cn' else 'kpn'
        # ResolvePath supports both legacy datadir-root and instance locations.
        # Override both read-only, so a retained legacy file cannot win lookup.
        extra=['--volume='+str(CONF/name)+':/data/'+prefix+name+':ro'
               for name in ('static-nodes.json','trusted-nodes.json') for prefix in ('','klay/')]
    argv=[*DOCKER,'run','--pull=never','--rm','--name='+CONTAINER,'--network=host','--read-only',
          '--label=erpc.owner='+state['owner'],'--label=erpc.role='+state['role'],'--label=erpc.network='+state['network'],
          '--cap-drop=ALL','--ulimit=core=0:0','--security-opt=no-new-privileges','--user='+str(uid)+':'+str(gid),
          '--stop-timeout=1800','--tmpfs=/tmp:rw,nosuid,nodev,size=1g',
          '--volume='+str(ROOT/'data')+':/data:rw','--volume='+str(identity_path)+':/identity:ro',*extra,
          '--entrypoint=/klaytn-docker-pkg/bin/'+executable,image(state),*arguments(state)]
    os.execve(argv[0],argv,environment())


def status(state):
    result={'network':state['network'],'storage':state['storage'],'phase':state['phase'],
            'service':active(),'ready':False,'installed':state.get('installed'),'target':state.get('target'),
            'startup_revoked':state.get('startup_revoked')}
    try:
        guard(state)
        container=check_container(state)
        require(container is not None and container.get('State',{}).get('Running')is True,'owned Kaia container is not running')
        require(isinstance(container.get('Id'),str) and re.fullmatch('[a-f0-9]{64}',container['Id']) and isinstance(container['State'].get('StartedAt'),str) and container['State']['StartedAt'],'owned Kaia process generation is unavailable')
        require(owned_ports(container['State'].get('Pid'),(8551,8552)),'owned Kaia process does not own RPC listeners')
        require(rpc('eth_chainId')==hex(network(state)['chain_id']),'Kaia network ID differs')
        genesis=rpc('eth_getBlockByNumber',['0x0',False])
        require(isinstance(genesis,dict) and genesis.get('hash')==network(state)['genesis'],'Kaia genesis differs')
        head=rpc('eth_getBlockByNumber',['latest',False]);sync=rpc('eth_syncing');peers=rpc('net_peerCount')
        require(isinstance(head,dict) and all(isinstance(head.get(key),str) and re.fullmatch('0x[a-fA-F0-9]{1,16}',head[key]) for key in ('number','timestamp')),'Kaia head is unavailable')
        require(isinstance(peers,str) and re.fullmatch('0x[a-fA-F0-9]{1,8}',peers),'Kaia peer count is unavailable')
        observed=check_container(state)
        require(observed is not None and observed.get('Id')==container.get('Id') and all(observed.get('State',{}).get(key)==container['State'].get(key) for key in ('Running','Pid','StartedAt')),'Kaia process changed during observation')
        require(owned_ports(observed['State'].get('Pid'),(8551,8552)),'Kaia listener changed during observation')
        age=int(time.time())-int(head['timestamp'],16)
        result.update(block=head['number'],block_age_seconds=age,peers=int(peers,16),syncing=sync,
                      ready=result['service']=='active' and sync is False and int(peers,16)>0 and -120<=age<=120)
    except Exception:
        result['ready']=False;result['inspection_error']='owned process, firewall, identity, network or synchronization unavailable'
    if state['role']=='validator':
        result.update(node_kind=state['node_kind'],public_identity=state.get('custody_public'),backup_confirmed=state.get('backup_confirmed')is True)
        try:
            result['registration']=corecell.observe(SimpleNamespace(**globals()),state,result)
            if state['node_kind']=='cn':
                result['node_ready']=result['ready']
                result['ready']=result['ready'] and all(result['registration'].get(key)is True for key in ('admission_observed','qualified_observed','staking_observed','gc_id_observed','bls_observed'))
        except Exception:
            result['registration']={'inspection_error':'public registration unavailable'};result['ready']=False
    return result


def deploy_intent(request):
    value=request.get('intent')
    require(isinstance(value,str) and re.fullmatch('[a-f0-9]{32}',value),'invalid Kaia deployment intent')
    return value


def check_deploy(state,request):
    require(state.get('deploy_intent')==deploy_intent(request) and state.get('deploy_target')==pin(request),'Kaia deployment cancelled or superseded')


def install(state,request):
    check_deploy(state,request)
    require(state['phase']=='installing' and state.get('target')==pin(request),'installation target differs')
    capacity(state,installation=True);stop(state)
    uid,gid=request.get('service_uid'),request.get('service_gid')
    require(all(type(v)is int and 100<=v<=65534 for v in (uid,gid)),'invalid Kaia service account')
    if 'service_uid' in state:
        require((state['service_uid'],state['service_gid'])==(uid,gid),'established Kaia service account differs')
    state.update(service_uid=uid,service_gid=gid);save(state)
    account(state);account_quiet(state)
    if state['role']=='validator':identity(state)
    run([*DOCKER,'pull',image(request)],timeout=7200);verify_image(request)
    identity(state,create=True)
    data=ROOT/'data';data.mkdir(mode=0o700,exist_ok=True)
    if state['storage']=='pruned':
        selected=snapshot(state)
        bootstrap.bootstrap(ROOT,state['owner'],selected,uid,gid,selected['uncompressed_bytes'])
    elif not state.get('genesis_initialized'):
        if not state.get('genesis_creating'):
            require(not any(data.iterdir()),'unowned full database cannot be adopted')
            state['genesis_creating']=True;save(state)
        require(all(path.relative_to(data).as_posix() in ('klay','klay/chaindata') and path.is_dir() and not path.is_symlink() for path in data.rglob('*')),'interrupted genesis initialization contains unowned data')
        (data/'klay/chaindata').mkdir(mode=0o700,parents=True,exist_ok=True)
        for path in (data/'klay/chaindata',data/'klay',data):
            os.chown(path,uid,gid)
            fd=os.open(path,os.O_DIRECTORY)
            try:os.fsync(fd)
            finally:os.close(fd)
        state['genesis_initialized']=True;state.pop('genesis_creating',None);save(state)
    else:require((data/'klay/chaindata').is_dir(),'established full database directory is missing')
    os.chown(data,uid,gid)
    if state['role']=='validator':corecell.publish_configuration(SimpleNamespace(**globals()),dict(state,**target_pin(request)))
    return {'artifacts':'qualified','bootstrap':'published' if state['storage']=='pruned' else 'genesis'}


def dispatch(state,request):
    check(state,request)
    action=request.get('action')
    if action=='status':return status(state)
    if action=='provision-account':return coreaccount.provision(SimpleNamespace(**globals()),state)
    if action=='time-service':
        require(state['role']=='validator','time-service selection requires core-cell role')
        names=('chrony.service','chronyd.service','ntp.service','ntpd.service','systemd-timesyncd.service')
        for name in names:
            if active(name)=='active':return {'service':name,'install':False}
        for name in names:
            if loaded(name):return {'service':name,'install':name=='systemd-timesyncd.service'}
        return {'service':'systemd-timesyncd.service','install':True}
    if action=='verify-helpers':return verify_publication()
    if action=='authorize-deploy':
        target=target_pin(request)
        if 'target' in state:require(state['target']==target,'resume the existing Kaia installation target')
        state.update(deploy_intent=deploy_intent(request),deploy_target=target);save(state)
        return {'authorized':True}
    if action in ('check-deploy','begin-install','install-artifacts','finish-install'):
        check_deploy(state,request)
    if action=='check-deploy':return {'authorized':True}
    if action=='begin-install':
        if state['role']=='validator':
            identity(state)
            corecell.configuration(SimpleNamespace(**globals()),dict(state,**target_pin(request)))
        target=pin(request);capacity(state,installation=True)
        old=state['installed'] if 'installed' in state else target_pin(state)
        require(tuple(map(int,target['version'].split('.')))>=tuple(map(int,old['version'].split('.'))),'Kaia database downgrades are refused')
        if target['version']==old['version']:require((target['commit'],target['image'])==(old['commit'],old['image']),'same-version source/image replacement is refused')
        if 'target' in state:require(state['target']==target,'resume the existing Kaia target')
        state.update(phase='installing',target=target,startup_revoked=True);save(state);stop(state)
        return {'phase':'installing'}
    if action=='install-artifacts':return install(state,request)
    if action=='finish-install':
        require(state['phase']=='installing' and state.get('target')==pin(request),'installation target differs')
        stop(state);verify_image(request)
        candidate=dict(state,**pin(request),phase='installed',installed=pin(request),startup_revoked=False,firewall=request['firewall'])
        candidate.pop('target',None);guard(candidate);save(candidate)
        return {'phase':'installed'}
    if action in ('start','restart'):
        require(pin(request)==state.get('installed'),'inventory differs from installed Kaia configuration')
        if 'intent' in request:check_deploy(state,request)
        else:state.update(deploy_intent=None,deploy_target=None)
        candidate=dict(state,startup_revoked=False);guard(candidate)
        if action=='restart':state['startup_revoked']=True;save(state);stop(state)
        state=candidate;save(state)
        run(['systemctl','enable',UNIT]);run(['systemctl','start',UNIT],timeout=240)
        require(active()=='active','Kaia service did not start')
        state.update(deploy_intent=None,deploy_target=None);save(state)
        return status(state)
    if action in ('stop','destroy'):
        return cancel_and_stop(state,retire=action=='destroy')
    raise Refused('unsupported Kaia operation')


def custody_dispatch(state,request):
    check(state,request)
    require(state['role']=='validator','concealed custody is only available to the dedicated core-cell owner')
    module=SimpleNamespace(**globals())
    action=request.get('action')
    if action=='custody-create':return custody.create(module,state)
    if action=='custody-export':return custody.read(module,state)[0]
    if action=='custody-confirm':return custody.acknowledge(module,state,request)
    if action=='custody-restore':
        raw=request.get('material')
        require(isinstance(raw,str) and len(raw)<=16384,'concealed recovery payload exceeds its bound')
        # Establish backup ownership before any shutdown; a rejected foreign
        # capsule cannot disturb the original running owner.
        custody.decode_payload(module,state,raw.encode())
        require(hashlib.sha256(raw.encode()).hexdigest()==state.get('custody_digest'),'backup differs from original custody')
        cancel_and_stop(state)
        return custody.restore(module,state,raw.encode())
    raise Refused('unsupported concealed custody action')


def locked(request,in_play=False,custody_mode=False):
    operation=None
    if not in_play and request.get('action')!='status':
        operation=os.open(OPERATION_ROOT,os.O_RDONLY)
        try:fcntl.flock(operation,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except Exception:
            os.close(operation);raise Refused('another node operation is active') from None
    try:
        fd=os.open(LOCK,os.O_CREAT|os.O_NOFOLLOW|os.O_RDWR,0o600)
        with os.fdopen(fd,'w')as stream:
            fcntl.flock(stream,fcntl.LOCK_EX)
            if custody_mode:return custody_dispatch(state_read(),request)
            return prepare(request) if request.get('action')=='prepare' else dispatch(state_read(),request)
    finally:
        if operation is not None:os.close(operation)


def main():
    os.umask(0o077);resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    require(os.geteuid()==0,'root is required')
    if sys.argv[1:]==['firewall-load']:
        state_read();firewall_controller().dispatch('load');return
    if len(sys.argv)==4 and sys.argv[1] in ('firewall-confirm','firewall-apply','firewall-require'):
        state_read()
        action={'firewall-confirm':'confirm','firewall-apply':'apply','firewall-require':'require-confirmed'}[sys.argv[1]]
        firewall_controller().dispatch(action,*sys.argv[2:]);return
    if sys.argv[1:]==['guard']:guard(state_read());return
    if sys.argv[1:]==['execute']:execute(state_read());return
    if sys.argv[1:]==['stop-container']:stop_container(state_read());return
    require(sys.argv[1:] in ([],['play'],['custody']),'unsupported Kaia invocation')
    raw=sys.stdin.buffer.read(65537);require(len(raw)<=65536,'Kaia request too large')
    request=json.loads(raw)
    result=locked(request,in_play=sys.argv[1:]==['play'],custody_mode=sys.argv[1:]==['custody'])
    if isinstance(result,bytes):
        require(sys.argv[1:]==['custody'],'concealed response cannot enter public output');sys.stdout.buffer.write(result)
    else:print(json.dumps(result))


if __name__=='__main__':
    try:load_dependencies();main()
    except Refused as error:print(str(error),file=sys.stderr);sys.exit(1)
    except Exception:print('Kaia operation failed; ownership and data retained',file=sys.stderr);sys.exit(1)
