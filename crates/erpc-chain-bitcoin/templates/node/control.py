#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Bitcoin lifecycle controller: exact host contract before every mutation.

Core authentication stays on the host via its private cookie. There are no wallet,
transaction, arbitrary-RPC or shell-command entry points.
"""
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shutil
import stat
import subprocess
import sys
import tarfile

ROOT = Path('/var/lib/erpc-bitcoin')
OPT = Path('/opt/erpc-bitcoin')
CONF = Path('/etc/erpc/bitcoin.conf')
UNIT = 'erpc-bitcoin'
LOCK = Path('/run/lock/erpc-bitcoin.lock')
HELPER = Path('/usr/local/lib/erpc/bitcoin-control')
UNIT_PATH = Path('/etc/systemd/system/erpc-bitcoin.service')
ROOT_UID = 0
ROOT_GID = 0
CATALOG = {'31.1': {'commit':'9be056a8a72b624dae9623b2f7bded92c2a21c91','artifacts':{
    'x86_64-linux-gnu':'b80d9c3e04da78fb6f0569685673418cf686fadba9042d926d13fb87ff503f9e',
    'aarch64-linux-gnu':'dcf1873f2208ba4f962f3398d47e154c39c0084be8f4553e05c940d0ace3d004'}}}
NETWORKS = {
    'mainnet': ('main', 8332, 8333, '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f'),
    'testnet4': ('testnet4', 48332, 48333, '00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043'),
    'signet': ('signet', 38332, 38333, '00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6'),
    'regtest': ('regtest', 18443, 18444, '0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206'),
}


class Refused(Exception):
    pass


def require(ok, message):
    if not ok:
        raise Refused(message)


def version(value):
    require(isinstance(value, str) and re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*))?', value), 'invalid release version')
    parts = tuple(int(p) for p in value.split('.'))
    parts += (0,) * (3 - len(parts))
    require(parts >= (31, 1, 0) and max(parts) <= 65535, 'unsupported release')
    return parts


def validate(request):
    require(isinstance(request.get('owner'), str) and re.fullmatch('[A-Za-z0-9]{1,80}', request['owner']), 'invalid owner')
    require(request.get('network') in NETWORKS, 'unsupported network')
    require(request.get('storage') in ('full', 'pruned'), 'unsupported storage')
    prune = request.get('prune_mib')
    require(type(prune) is int and ((request['storage'] == 'full' and prune == 0) or
            (request['storage'] == 'pruned' and 550 <= prune <= 9223372036854775807)), 'invalid prune contract')
    if 'host_binding' in request:
        require(isinstance(request['host_binding'],str) and re.fullmatch('[a-f0-9]{64}',request['host_binding']),
                'invalid original Bitcoin host binding')


def contract(request):
    result = {key: request[key] for key in ('owner', 'network', 'storage', 'prune_mib')}
    if 'host_binding' in request: result['host_binding'] = request['host_binding']
    return result


def configuration(state):
    chain, rpc_port, peer_port, _ = NETWORKS[state['network']]
    return (f'chain={chain}\nserver=1\ndaemon=0\ndisablewallet=1\nrest=0\ndbcache=1024\n'
            f'prune={state["prune_mib"]}\ntxindex={int(state["storage"] == "full")}\n\n'
            f'[{chain}]\nrpcbind=127.0.0.1\nrpcallowip=127.0.0.1\nrpcport={rpc_port}\nport={peer_port}\n')


def protected(path, directory=False, missing=False):
    """Reject unknown writable ancestors before accepting an ownership receipt."""
    require(path.is_absolute() and '..' not in path.parts, 'invalid protected path')
    for ancestor in reversed(path.parents):
        if not ancestor.exists():
            require(missing and not ancestor.is_symlink(), 'protected ancestor is missing')
            continue
        info = ancestor.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, ROOT_UID) and
                not info.st_mode & 0o022, 'unsafe protected ancestor')
    if not path.exists() and not path.is_symlink():
        require(missing, 'original protected path is missing')
        return
    info = path.lstat()
    require(info.st_uid == ROOT_UID and not info.st_mode & 0o022 and
            (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1),
            'protected path owner, kind or permissions changed')


def protected_paths():
    protected(ROOT, directory=True, missing=True)
    protected(OPT, directory=True, missing=True)
    protected(CONF, missing=True)
    protected(HELPER, missing=True)
    protected(UNIT_PATH, missing=True)
    overrides = UNIT_PATH.with_name(UNIT_PATH.name + '.d')
    protected(overrides, directory=True, missing=True)
    require(not overrides.exists() or not any(overrides.iterdir()),
            'unknown Bitcoin systemd overrides require explicit operator recovery')


def synchronize(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic(path, value, mode=0o600):
    protected(path, missing=True)
    temporary = path.with_name(path.name + '.new')
    protected(temporary, missing=True)
    if path in (ROOT/'owner.json',ROOT/'cancelled.json'):
        preserve_pending_cancellation()
    temporary.unlink(missing_ok=True)
    fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_WRONLY, mode)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(),mode)
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    synchronize(path.parent)


def cancellation_record():
    """Visible pending writes restrict execution, even before their fsync/rename.

    They never authorize a start or replace original ownership. An interrupted
    owner write also fences continuation until a new explicit operation commits
    a later generation; a restrictive retirement survives a stop retry.
    """
    result={'stopped':False,'generation':0,'retired':False}
    committed=ROOT/'owner.json'
    if committed.exists() or committed.is_symlink():
        protected(committed)
        require(committed.stat().st_size<=65536,'original owner exceeds its bound')
        owner=json.loads(committed.read_bytes());validate(owner)
        if owner.get('stopped') is True:
            require(type(owner.get('generation',0)) is int and 0<=owner.get('generation',0)<2**63,
                    'invalid committed stop generation')
            result.update(stopped=True,generation=owner.get('generation',0),
                          retired=owner.get('phase') in ('retired','v2:retired','v3:retired'))
    history=ROOT/'cancellation-history'
    if history.exists() or history.is_symlink():
        protected(history,directory=True)
        rows=list(history.iterdir())
        require(len(rows)<=256,'too many retained cancellation records')
        for path in rows:
            protected(path)
            require(re.fullmatch(r'[a-f0-9]{64}\.json(?:\.new)?',path.name), 'unknown retained cancellation entry')
            # A staging write is never sole authority: its original pending
            # source is kept until the completed record crosses every barrier.
            if path.name.endswith('.new'):continue
            require(path.stat().st_size<=65536,'retained cancellation exceeds its bound')
            raw=path.read_bytes();value=json.loads(raw)
            require(hashlib.sha256(raw).hexdigest()+'.json'==path.name and isinstance(value,dict) and
                    set(value)=={'stopped','generation','retired'} and value['stopped'] is True and
                    type(value['retired']) is bool and type(value['generation']) is int and
                    0<=value['generation']<2**63, 'invalid retained cancellation record')
            result['stopped']=True
            result['generation']=max(result['generation'],value['generation'])
            result['retired']=result['retired'] or value['retired']
    for name in ('cancelled.json','cancelled.json.new'):
        path=ROOT/name
        if not path.exists() and not path.is_symlink():continue
        protected(path)
        require(path.stat().st_size<=65536,'cancellation fence exceeds its bound')
        try:value=json.loads(path.read_bytes())
        except (ValueError,UnicodeError):
            require(result['stopped'] and name.endswith('.new'), 'incomplete cancellation lacks retained restrictive authority')
            continue
        require(isinstance(value,dict) and set(value)=={'stopped','generation'} and value['stopped'] is True and
                type(value['generation']) is int and 0<=value['generation']<2**63,
                'invalid cancellation fence')
        result['stopped']=True
        result['generation']=max(result['generation'],value['generation'])
    pending=ROOT/'owner.json.new'
    if pending.exists() or pending.is_symlink():
        protected(pending);protected(ROOT/'owner.json')
        require(pending.stat().st_size<=65536 and (ROOT/'owner.json').stat().st_size<=65536,
                'pending original owner exceeds its bound')
        try:value=json.loads(pending.read_bytes())
        except (ValueError,UnicodeError):
            require(result['stopped'], 'incomplete pending owner lacks retained restrictive authority')
            return result
        original=json.loads((ROOT/'owner.json').read_bytes())
        validate(value);validate(original)
        require(all(value.get(key)==item for key,item in contract(original).items()),
                'pending owner belongs to another original contract')
        require(value.get('phase') in ('v3:prepared','v3:installing','v3:installed','v3:retired') and
                type(value.get('generation',0)) is int and 0<=value.get('generation',0)<2**63,
                'unknown pending original ownership format')
        result['stopped']=True
        result['generation']=max(result['generation'],value.get('generation',0))
        result['retired']=result['retired'] or value['phase']=='v3:retired'
    return result


def preserve_pending_cancellation():
    """Keep restrictive evidence before reusing either mutable staging name.

    This runs before unlink/open/write, including stop retries. Completed
    content-addressed records are immutable and re-synced on every retry. A
    failed record publication leaves the old pending file untouched.
    """
    if not (ROOT/'owner.json').exists():return
    fence=cancellation_record()
    if not fence['stopped']:return
    raw=json.dumps(fence,sort_keys=True,separators=(',',':')).encode()
    directory=ROOT/'cancellation-history'
    protected(directory,directory=True,missing=True)
    directory.mkdir(mode=0o700,exist_ok=True)
    protected(directory,directory=True)
    synchronize(directory);synchronize(ROOT)
    path=directory/(hashlib.sha256(raw).hexdigest()+'.json')
    if path.exists() or path.is_symlink():
        protected(path)
        require(path.read_bytes()==raw,'retained cancellation bytes changed')
    else:atomic(path,raw)
    synchronize(path);synchronize(directory);synchronize(ROOT)


def stopped():
    return cancellation_record()['stopped']


def generation(state):
    value = state.get('generation', 0)
    require(type(value) is int and 0 <= value < 2**63 - 1, 'invalid operation generation')
    return max(value, cancellation_record()['generation'])


def intent(request):
    value = request.get('intent')
    require(isinstance(value, str) and re.fullmatch('[a-f0-9]{32}', value), 'invalid deployment intent')
    return value


def pending(state, request):
    require(not stopped() and not state.get('stopped',False) and state.get('intent') == intent(request),
            'deployment was cancelled or superseded')
    require(type(request.get('generation')) is int and request['generation']+1==generation(state),
            'deployment generation was cancelled or superseded')
    require(release_pin(request) == state.get('target'), 'deployment target changed')
    require(request.get('controller_sha256') == state.get('controller_sha256'), 'deployment controller changed')
    unit = request.get('unit')
    require(isinstance(unit, str) and len(unit) <= 32768 and
            hashlib.sha256(unit.encode()).hexdigest() == state.get('unit_sha256'), 'deployment unit changed')


def read_state():
    protected(ROOT, directory=True)
    path = ROOT / 'owner.json'
    protected(path)
    state = json.loads(path.read_text())
    validate(state)
    # Original legacy records remain readable for scoped emergency shutdown.
    # Once saved, an older helper's closed phase parser rejects this protocol.
    if isinstance(state.get('phase'), str) and state['phase'].startswith(('v2:','v3:')):
        state['phase'] = state['phase'][3:]
    require(state.get('phase') in ('prepared', 'installing', 'installed', 'retired'), 'unknown Bitcoin ownership format')
    return state


def save(state):
    protected(ROOT, directory=True)
    value = dict(state, phase='v3:' + state['phase'])
    atomic(ROOT / 'owner.json', json.dumps(value, sort_keys=True).encode())


def run(argv, timeout=120, allowed=(0,), environment=None):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout, check=False, env=environment)
    require(result.returncode in allowed, 'Bitcoin service operation failed; inspect the owned service journal')
    return result.stdout


def as_original(account, argv, timeout=120):
    return run(['/usr/bin/setpriv','--reuid',str(account['uid']),'--regid',str(account['gid']),
                '--clear-groups','--no-new-privs','--bounding-set=-all','--inh-caps=-all','--ambient-caps=-all','--',*argv],
               timeout=timeout, environment={'PATH':'/usr/bin:/bin','HOME':str(ROOT/'data'),'LC_ALL':'C.UTF-8'})


def loaded(unit=UNIT):
    result = run(['/usr/bin/systemctl', 'show', '--property=LoadState', '--value', unit], allowed=(0, 1)).strip()
    require(result in (b'not-found', b'loaded', b'masked'), 'could not determine service ownership')
    return result != b'not-found'


def active():
    result = subprocess.run(['/usr/bin/systemctl', 'is-active', UNIT], capture_output=True, check=False)
    return result.stdout.decode().strip()


def stop(state=None):
    if state is None: state=read_state()
    if state.get('origin') in ('fresh','verified-legacy') and (ROOT/'account-intent.json').exists():
        drain_original(state)
    else:
        drain_legacy()


def cli(method, *arguments):
    return inspect_rpc(read_state(), method, arguments)


def check(state, request, inspect_config=True):
    validate(request)
    original = contract(state); supplied = contract(request)
    if 'host_binding' not in original: supplied.pop('host_binding',None)
    require(original == supplied, 'Bitcoin host ownership/network/retention mismatch; nothing changed')
    if not inspect_config:
        return
    protected_paths()
    require(not (ROOT / 'data').is_symlink(), 'unsafe Bitcoin data directory')
    if CONF.exists() or CONF.is_symlink():
        require(CONF.is_file() and not CONF.is_symlink() and CONF.read_text() == configuration(state), 'Bitcoin configuration differs from its immutable host contract')
    else:
        require(state['phase'] in ('prepared', 'installing', 'retired') and not state.get('installed'), 'Bitcoin configuration missing; refusing mutation')


def capacity(state):
    """Reserve unfinished sync space plus headroom from actual host allocation.

    Never infer a completed bootstrap from an inventory verb or installed binary.
    Count only Core database directories, not logs or arbitrary data files. GNU du
    reports allocated bytes on this filesystem; sparse apparent size is not credit.
    """
    data = ROOT / 'data'
    require(not data.is_symlink(), 'unsafe Bitcoin data directory')
    network_data = data if state['network'] == 'mainnet' else data / NETWORKS[state['network']][0]
    require(not network_data.is_symlink(), 'unsafe Bitcoin network directory')
    allocated = 0
    for name in ('blocks', 'chainstate', 'indexes'):
        path = network_data / name
        require(not path.is_symlink(), 'unsafe Bitcoin database directory')
        if path.exists():
            require(path.is_dir(), 'invalid Bitcoin database directory')
            raw = run(['/usr/bin/du', '-sx', '-B1', str(path)]).split()
            require(raw and raw[0].isdigit(), 'cannot measure Bitcoin database allocation')
            allocated += int(raw[0])
    probe = data
    while not probe.exists():
        probe = probe.parent
    free = shutil.disk_usage(probe).free
    if state['network'] == 'regtest':
        initial, reserve = 10_000_000_000, 1_000_000_000
    elif state['storage'] == 'pruned':
        initial = state['prune_mib'] * 1_048_576 + 100_000_000_000
        reserve = 100_000_000_000
    else:
        initial = {'mainnet': 1500, 'testnet4': 200, 'signet': 100}[state['network']] * 1_000_000_000
        reserve = 50_000_000_000
    require(free >= max(reserve, initial - allocated),
            'insufficient free storage for remaining initial sync and operating headroom; nothing started')


def prepare(request):
    validate(request)
    qualified_pin(request)
    protected_paths()
    if not (ROOT/'owner.json').exists(): recover_initial_owner(request)
    if (ROOT / 'owner.json').exists():
        state = read_state()
        check(state, request)
        if request.get('intent') is not None: pending(state,request)
        original_runtime(state,account_required=False)
        capacity(state)
        data_before_accounts(state)
        account = account_ensure(state)
        prepare_data(state,account)
        return {'phase': state['phase'], 'already_owned': True}
    # A failed initialization never grants authority over a pre-existing daemon/datadir.
    require(not loaded() and not loaded('bitcoind'), 'an unowned Bitcoin service exists')
    require(not any(path.exists() or path.is_symlink() for path in (CONF,HELPER,UNIT_PATH)) and
            (not OPT.exists() or not any(OPT.iterdir())), 'unowned Bitcoin runtime artifacts exist')
    require('host_binding' in request, 'fresh Bitcoin preparation requires original SSH host binding')
    layout = initial_layout()
    account_plan()
    ROOT.mkdir(mode=0o755, parents=True, exist_ok=True)
    synchronize(ROOT.parent)
    root_inode = ROOT.lstat().st_ino
    require(layout['root_inode'] is None or layout['root_inode']==root_inode,
            'prepared original ROOT changed before reservation')
    layout['root_inode'] = root_inode
    state = dict(contract(request), phase='prepared', origin='fresh', layout=layout,
                 machine_sha256=machine_identity(), data_ready=False,source_started=False)
    root_volume,_ = verify_layout(state)
    capacity(state)
    descriptor = os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        require(opened.st_uid==ROOT_UID and opened.st_ino==root_inode and opened.st_dev==root_volume['device'],
                'prepared ROOT changed while opening its original directory')
        os.fchmod(descriptor,0o755); os.fsync(descriptor)
        current = ROOT.lstat()
        require((current.st_dev,current.st_ino)==(opened.st_dev,opened.st_ino), 'prepared ROOT changed during provisioning')
    finally: os.close(descriptor)
    synchronize(ROOT.parent)
    save(state)
    account = account_ensure(state)
    prepare_data(state,account)
    return {'phase': 'prepared'}


def release_pin(request):
    pin = request['pin']
    require(isinstance(pin,dict) and set(pin)=={'version','commit','sha256','platform'}, 'invalid closed native source pin')
    version(pin['version'])
    require(re.fullmatch('[a-f0-9]{40}', pin['commit']) and re.fullmatch('[a-f0-9]{64}', pin['sha256']), 'invalid release pin')
    require(pin['platform'] in ('x86_64-linux-gnu', 'aarch64-linux-gnu'), 'unsupported release platform')
    return pin


def release_dir(pin):
    return OPT / 'releases' / (pin['version'] + '-' + pin['platform'])


def qualified_pin(request):
    pin=release_pin(request);catalog=CATALOG.get(pin['version'])
    require(catalog is not None and pin['commit']==catalog['commit'] and
            pin['sha256']==catalog['artifacts'].get(pin['platform']),
            'native target is outside the source-qualified catalog; existing data is retained')
    return pin


def native_version(output, expected):
    # 31.1 bitcoind.cpp ProcessInitCommands plus init/bitcoind.cpp exeName.
    # FormatFullVersion uses the release tag, or the release CMake x.y.z tuple.
    require(isinstance(output, bytes) and 0 < len(output) <= 65536,
            'native release version output is missing or excessive')
    first = output.splitlines()[0].decode('ascii')
    match = re.fullmatch(r'Bitcoin Core daemon version v([0-9]+\.[0-9]+(?:\.[0-9]+)?) bitcoind', first)
    require(match is not None and version(match[1]) == version(expected),
            'native version differs from authenticated release')


def guard(state, explicit_start=False):
    protected_paths()
    original_runtime(state)
    check(state, state)
    capacity(state)
    require(state['phase'] == 'installed' and not cancellation_record()['retired'],
            'Bitcoin installation is incomplete or retired')
    require(state.get('intent') is None, 'Bitcoin deployment has not been explicitly activated')
    require(explicit_start or (not stopped() and not state.get('stopped', False)), 'Bitcoin runtime is explicitly stopped')
    pin = qualified_pin({'pin': state['installed']})
    verified_native(state)
    floor = check_source_floor(state,pin)
    require(explicit_start or floor==pin, 'current native source has not crossed its durable DB-opening barrier')
    directory = release_dir(pin)
    protected(directory, directory=True)
    protected(directory / 'bin', directory=True)
    for name in ('bitcoind', 'bitcoin-cli'):
        protected(directory / 'bin' / name)
    require((OPT / 'current').is_symlink() and (OPT / 'current').resolve() == release_dir(pin).resolve(), 'Bitcoin binary selection differs from verified release')
    marker = release_dir(pin) / 'verified.json'
    require(marker.is_file() and not marker.is_symlink() and json.loads(marker.read_text()) == pin, 'Bitcoin release verification marker missing')
    # The manager's loaded policy is the executable authority; matching only
    # on-disk bytes cannot exclude a cached override/hook or wrong recipient.
    unit_authority(state)


def cancellation(state, retire=False):
    """Attempt both persistent barriers and owned shutdown even on storage failure."""
    failures = []
    state['stopped'] = True
    try:
        fence=cancellation_record()
        retire=retire or fence['retired']
        value = generation(state) + 1
        state['generation'] = value
        atomic(ROOT / 'cancelled.json', json.dumps({'stopped': True, 'generation': value}).encode())
    except Exception:
        failures.append('cancellation fence')
    state['intent'] = None
    if retire:
        state['phase'] = 'retired'
    try:
        save(state)
    except Exception:
        failures.append('original state')
    try:
        stop(state)
    except Exception:
        failures.append('shutdown')
    try:
        disable_original_boot(state)
    except Exception:
        failures.append('boot disable')
    require(not failures, 'Bitcoin cancellation or shutdown failed; original data retained and resume refused')
    return {'phase': state['phase'], 'service': 'stopped', 'data_preserved': True, 'ownership_preserved': True}


def clear_cancellation():
    # Only a durable later explicit authorization/start may consume both forms
    # of a cancellation. Failed cleanup leaves any remaining form restrictive.
    state=read_state();fence=cancellation_record()
    require(not state.get('stopped',False) and not (ROOT/'owner.json.new').exists() and
            (not fence['stopped'] or state.get('generation',0)>fence['generation']),
            'a durable later original operation is required to clear cancellation')
    synchronize(ROOT/'owner.json');synchronize(ROOT)
    for name in ('cancelled.json','cancelled.json.new'):
        path=ROOT/name;protected(path,missing=True)
        path.unlink(missing_ok=True)
        synchronize(ROOT)
    history=ROOT/'cancellation-history'
    if history.exists():
        protected(history,directory=True)
        for path in history.iterdir():
            protected(path)
            path.unlink()
            synchronize(history)
        synchronize(ROOT)


def install_artifacts(state, request):
    """Short serialized live publication; downloads run before this operation.

    The caller's cancellation lock covers every binary/config/unit replacement.
    A pending download may finish after stop, but cannot enter this operation.
    """
    pending(state, request)
    account = original_runtime(state)
    require(state['phase'] == 'installing', 'installation target is not fenced')
    capacity(state)
    stop()
    pin = qualified_pin(request)
    directory = release_dir(pin)
    archive = OPT / ('bitcoin-' + pin['version'] + '-' + pin['platform'] + '.tar.gz')
    protected(archive)
    digest = hashlib.sha256()
    with archive.open('rb') as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    require(digest.hexdigest() == pin['sha256'], 'authenticated archive bytes changed')
    for path in (OPT,OPT/'releases',directory,directory/'bin'):
        protected(path,directory=True,missing=True)
        path.mkdir(mode=0o700,exist_ok=True)
        fd = os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            os.fchmod(fd,0o755); os.fsync(fd)
        finally: os.close(fd)
        synchronize(path.parent)
    hashes = {}
    with tarfile.open(archive,'r:gz') as bundle:
        members = bundle.getmembers()
        require(len(members)<=10000, 'authenticated archive has an unexpected member count')
        for name in ('bitcoind','bitcoin-cli'):
            full = 'bitcoin-' + pin['version'] + '/bin/' + name
            selected = [member for member in members if member.name==full]
            require(len(selected)==1 and selected[0].isreg() and 0 < selected[0].size <= 256*1024*1024,
                    'authenticated native executable is not a unique bounded regular member')
            stream = bundle.extractfile(selected[0])
            require(stream is not None, 'authenticated native archive member is unavailable')
            with stream:
                raw = stream.read(selected[0].size+1)
            require(len(raw)==selected[0].size, 'authenticated native executable was truncated')
            atomic(directory/'bin'/name,raw,0o755)
            hashes[name] = hashlib.sha256(raw).hexdigest()
    register_native(state,pin,hashes['bitcoind'],hashes['bitcoin-cli'])
    output = as_original(account,[str(directory / 'bin/bitcoind'),'-nosettings','-conf=/dev/null',
                                  '-datadir='+str(ROOT/'data'),'--version'])
    native_version(output, pin['version'])
    atomic(directory / 'verified.json', json.dumps(pin, sort_keys=True).encode(), 0o644)
    atomic(CONF, configuration(state).encode(), 0o640)
    os.chown(CONF, ROOT_UID, account['gid'])
    synchronize(CONF)
    carried=Path(__file__)
    protected(carried)
    require(carried.stat().st_size<=524288,'carried controller exceeds its source bound')
    source=carried.read_bytes()
    require(hashlib.sha256(source).hexdigest()==state['controller_sha256'], 'sealed carried controller differs from its authorized source')
    atomic(HELPER,source,0o755)
    atomic(UNIT_PATH, request['unit'].encode(), 0o644)
    current = OPT / 'current'
    require(not current.exists() or current.is_symlink(), 'unexpected live release path')
    temporary = OPT / ('current.' + intent(request) + '.new')
    if temporary.exists() or temporary.is_symlink():
        metadata = temporary.lstat()
        require(stat.S_ISLNK(metadata.st_mode) and metadata.st_uid==ROOT_UID and metadata.st_nlink==1 and
                os.readlink(temporary)==str(directory), 'unrecognized pending release publication')
    else:
        temporary.symlink_to(directory)
        synchronize(OPT)
    os.replace(temporary, current)
    synchronize(OPT)
    run(['/usr/bin/systemctl', 'daemon-reload'])
    state.update(phase='installed', installed=pin)
    save(state)
    return {'phase': 'installed', 'activation_pending': True}


def status(state):
    result = {'phase': state['phase'], 'service': active(), 'network': state['network'], 'rpc_available': False,
              'installed': state.get('installed'), 'target': state.get('target'),
              'process_owned': False, 'source_current': False,
              'generation': generation(state), 'stopped': stopped() or state.get('stopped', False)}
    result['authority_valid'] = False
    try:
        account = original_runtime(state)
        result.update(authority_valid=True,service_uid=account['uid'],service_gid=account['gid'])
    except (Refused,KeyError,ValueError,OSError):
        result['authority_error'] = 'original account, host or volume authority is incomplete or changed'
        return result
    if state['phase'] != 'installed' or result['service'] != 'active': return result
    try:
        pin=qualified_pin({'pin':state['installed']})
        require(check_source_floor(state,pin)==pin, 'running source lacks its original durable floor')
        result['source_current'] = True
        observed = running_process(state, sockets=True)
        result['process_owned'] = True
        result['blockchain'] = cli('getblockchaininfo')
        result['genesis'] = cli('getblockhash', '0')
        result['indexes'] = cli('getindexinfo')
        network = cli('getnetworkinfo')
        result['connections'] = network['connections']
        result['version'] = network['version']
        block_hash = result['blockchain']['bestblockhash']
        require(re.fullmatch('[a-f0-9]{64}', block_hash), 'invalid best block hash')
        result['tip_time'] = cli('getblockheader', block_hash)['time']
        require(observed == running_process(state, sockets=True), 'native generation changed during status')
        result['rpc_available'] = True
    except (Refused, KeyError, ValueError, OSError, http.client.HTTPException):
        result['inspection_error'] = 'RPC unavailable, warming up or malformed; readiness is not established'
    return result


def dispatch(state, request):
    action = request.get('action')
    check(state, request, inspect_config=action not in ('stop', 'destroy'))
    if action in ('stop','destroy') and state.get('origin') in ('fresh','verified-legacy'):
        retained_origin(state)
    if action == 'migrate-original':
        return migrate_original(state,request)
    if action == 'status':
        return status(state)
    if action == 'authorize':
        account = original_runtime(state)
        value = intent(request)
        prior = generation(state)
        require(type(request.get('generation')) is int and request['generation'] == prior,
                'deployment authorization was cancelled or superseded')
        pin = qualified_pin(request)
        if (ROOT/'native-releases.json').exists(): check_source_floor(state,pin,new_open=True)
        if state.get('installed'):
            require(version(pin['version']) >= version(state['installed']['version']), 'database downgrades are refused')
        unit = request.get('unit')
        require(isinstance(unit, str) and len(unit) <= 32768, 'missing fixed service unit')
        require([line for line in unit.splitlines() if line.startswith('User=')]==['User='+str(account['uid'])] and
                [line for line in unit.splitlines() if line.startswith('Group=')]==['Group='+str(account['gid'])],
                'deployment unit does not select the original numeric account')
        controller = request.get('controller_sha256')
        require(isinstance(controller,str) and re.fullmatch('[a-f0-9]{64}',controller), 'missing carried controller receipt')
        unit_sha = hashlib.sha256(unit.encode()).hexdigest()
        receipts = state.get('unit_receipts',[])
        require(isinstance(receipts,list) and all(isinstance(row,str) and re.fullmatch('[a-f0-9]{64}',row) for row in receipts),
                'invalid original service history')
        receipts = sorted(set([*receipts,*([state['unit_sha256']] if state.get('unit_sha256') else []),unit_sha]))
        require(len(receipts)<=128, 'original service history exceeds its bound')
        state.update(intent=value, target=pin, generation=prior + 1, stopped=False,
                     unit_sha256=unit_sha,unit_receipts=receipts,controller_sha256=controller)
        save(state)
        clear_cancellation()
        return {'intent': value, 'authorized': True}
    if action == 'begin-install':
        pending(state, request)
        original_runtime(state)
        capacity(state)
        pin = qualified_pin(request)
        if state.get('installed'):
            require(version(pin['version']) >= version(state['installed']['version']), 'database downgrades are refused')
        if state['phase'] == 'installing':
            require(state['target'] == pin, 'resume the interrupted target before changing release')
        state.update(phase='installing', target=pin)
        try:
            save(state)  # Reboots cannot start a partly installed release.
            stop()
        except Exception:
            cancellation(state)
            raise
        return {'phase': 'installing'}
    if action == 'install-artifacts':
        return install_artifacts(state, request)
    if action == 'activate':
        pending(state, request)
        require(state['phase'] == 'installed', 'deployment has not published a complete release')
        try:
            original_runtime(state)
            verified_native(state)
            reserve_source(state)
            state['source_started'] = True
            state['intent'] = None
            state.pop('target', None)
            save(state)
            guard(state)
            run(['/usr/bin/systemctl', 'enable', UNIT])
            run(['/usr/bin/systemctl', 'start', UNIT])
            require(active() == 'active', 'Bitcoin service did not start')
        except Exception:
            cancellation(state)
            raise
        return status(state)
    if action in ('start', 'restart'):
        prior = generation(state)
        require(type(request.get('generation')) is int and request['generation'] == prior,
                'service start request was cancelled or superseded')
        require(release_pin(request) == state.get('installed'), 'inventory release differs from installed release; resume deployment')
        guard(state, explicit_start=True)
        if action == 'restart':
            stop()
        try:
            reserve_source(state)
            state['stopped'] = False
            state['generation'] = prior + 1
            save(state)
            clear_cancellation()
            run(['/usr/bin/systemctl', 'enable', UNIT])
            run(['/usr/bin/systemctl', 'start', UNIT])
            require(active() == 'active', 'Bitcoin service did not start')
        except Exception:
            cancellation(state)
            raise
        return status(state)
    if action == 'stop':
        return cancellation(state)
    if action == 'destroy':
        return cancellation(state, retire=True)
    raise Refused('unsupported Bitcoin lifecycle operation')


def locked(request):
    # The lock's parent is root-owned; it is separate from the owner/data directory.
    fd = os.open(LOCK, os.O_CREAT | os.O_NOFOLLOW | os.O_RDWR, 0o600)
    with os.fdopen(fd, 'w') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == ROOT_UID and info.st_nlink == 1 and
                not info.st_mode & 0o077, 'unsafe Bitcoin operation lock')
        fcntl.flock(stream, fcntl.LOCK_EX)
        if request.get('action') == 'prepare':
            return prepare(request)
        return dispatch(read_state(), request)


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    require(os.geteuid() == 0, 'root is required')
    if sys.argv[1:] == ['guard']:
        state=read_state()
        guard(state)
        quiet_original(state)
        return
    raw = sys.stdin.buffer.read(1024 * 1024 + 1)
    require(len(raw) <= 1024 * 1024, 'request too large')
    print(json.dumps(locked(json.loads(raw))))


if __name__ == '__main__':
    try:
        main()
    except Refused as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
    except Exception:
        print('Bitcoin operation failed; inspect the owned service journal', file=sys.stderr)
        sys.exit(1)
