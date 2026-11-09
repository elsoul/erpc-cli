#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""BSC host lifecycle, with exact network/retention ownership before mutation."""
import fcntl
import hashlib
import grp
import pwd
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
import zipfile

from types import SimpleNamespace

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

class Refused(RuntimeError):
    pass


def require(condition,message):
    if not condition:raise Refused(message)


def load_dependencies():
    global bootstrap, validator, require, Refused
    trusted_imports(str(Path(__file__).parent))
    import bootstrap as loaded_bootstrap
    import validator as loaded_validator
    bootstrap,validator=loaded_bootstrap,loaded_validator
    require,Refused=bootstrap.require,bootstrap.Refused


ROOT_UID = 0
TRUST_ANCHOR = Path('/')
ROOT = Path('/var/lib/erpc-bsc')
CONF = Path('/etc/erpc/bsc')
OPT = Path('/opt/erpc-bsc')
HELPERS = Path('/usr/local/lib/erpc/bsc')
UNIT_DIRECTORY = Path('/etc/systemd/system')
LAUNCHER = Path('/usr/local/lib/erpc/bsc-control')
CATALOG = Path(__file__).resolve().with_name('catalog.json')
CATALOG_SHA = 'e2b5b692921c3297fa82e8f42b8fd41cd264f074c655b88eac24e9a5cc4b48a0'
LOCK = Path('/run/lock/erpc-bsc.lock')
OPERATION_ROOT = Path('/opt/erpc')
PROC = Path('/proc')
UNIT = 'erpc-bsc'
ACCOUNT = 'erpc-bsc'


def catalog(network):
    require(CATALOG.is_file() and not CATALOG.is_symlink(), 'BSC catalog is missing or unsafe')
    raw = CATALOG.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == CATALOG_SHA, 'BSC catalog differs from the reviewed pin')
    return json.loads(raw)[network]


def validate(request, pin_required=True):
    require(isinstance(request, dict), 'invalid BSC request')
    require(request.get('network') in ('mainnet', 'chapel'), 'unsupported BSC network')
    require(request.get('role') in ('rpc','validator'), 'unsupported BSC host role')
    if request['role'] == 'validator':
        require(isinstance(request.get('operator'),str) and re.fullmatch('0x[a-f0-9]{40}',request['operator']) and int(request['operator'][2:],16)!=0, 'invalid external financial operator')
    require(request.get('platform') in ('amd64', 'arm64'), 'unsupported BSC platform')
    require(request.get('storage') in ('full', 'pruned'), 'unsupported BSC retention')
    require(isinstance(request.get('owner'), str) and re.fullmatch('[a-z0-9]{1,80}', request['owner']), 'invalid BSC owner')
    require(isinstance(request.get('config_id'), str) and re.fullmatch('[a-f0-9]{64}', request['config_id']), 'invalid configuration identity')
    profile = catalog(request['network'])
    snapshot = profile['snapshots'].get(request.get('snapshot'))
    require(snapshot is not None and snapshot['retention'] == request['storage'], 'snapshot is not qualified for this network/retention')
    if pin_required:
        release = profile['releases'].get(request.get('version'))
        require(release is not None and release['commit'] == request.get('commit'), 'unreviewed BSC release')


def contract(state):
    result = {key: state[key] for key in ('owner', 'network', 'role', 'platform', 'storage', 'snapshot')}
    if state['role']=='validator': result['operator']=state['operator']
    return result


def release(state):
    return catalog(state['network'])['releases'][state['version']]


def target_pin(state):
    # The installed helper may predate a newly reviewed release. Authorization
    # records bounded metadata only; the carried helper qualifies it before use.
    require(isinstance(state.get('version'), str) and re.fullmatch(r'(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})', state['version']) and all(int(v) <= 65535 for v in state['version'].split('.')), 'invalid BSC target version')
    require(isinstance(state.get('commit'), str) and re.fullmatch('[a-f0-9]{40}', state['commit']), 'invalid BSC target commit')
    return {key: state[key] for key in ('version', 'commit', 'config_id')}


def pin(state):
    validate(state)
    return target_pin(state)


def binary(state):
    validate(state)
    return OPT / state['version'] / state['platform'] / 'geth'


def protected_directory(path):
    """A writable ancestor permits replacement of even a private root-owned file."""
    require(path.is_absolute() and os.path.normpath(path) == str(path), 'invalid BSC protected path')
    current = TRUST_ANCHOR
    for part in (None, *path.relative_to(TRUST_ANCHOR).parts):
        if part is not None: current = current / part
        try: info = current.lstat()
        except FileNotFoundError: continue
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == ROOT_UID and info.st_mode & 0o022 == 0,
                'BSC protected paths require real root-owned nonwritable ancestors')


def protected_file(path, private=False, missing=True):
    protected_directory(path.parent)
    try: info = path.lstat()
    except FileNotFoundError:
        require(missing, 'BSC ownership or helper is missing'); return
    require(stat.S_ISREG(info.st_mode) and info.st_uid == ROOT_UID and info.st_nlink == 1 and
            info.st_mode & (0o177 if private else 0o022) == 0,
            'unsafe BSC owner or privileged file')
    if private: require(info.st_size <= 65536, 'oversized BSC owner receipt')


def owned_units():
    return (UNIT + '.service', UNIT + '-firewall.service', UNIT + '-activation.service', UNIT + '-activation.timer')


def protected_paths():
    for path in (ROOT, ROOT / 'identity', CONF, OPT, HELPERS, UNIT_DIRECTORY): protected_directory(path)
    protected_file(LAUNCHER)
    protected_file(HELPERS.parent / 'rpc-firewall.py')
    dropins = [UNIT_DIRECTORY / (name + '.d') for name in owned_units()]
    for name in owned_units(): protected_file(UNIT_DIRECTORY / name)
    for directory in dropins:
        protected_directory(directory)
        if directory.exists():
            require(all(path.name in ('50-erpc-firewall-guard.conf', '50-erpc-firewall-guard.conf.new') for path in directory.iterdir()),
                    'unmanaged BSC systemd drop-ins cannot change the guarded service')
    for name in ('owner.json', 'owner.new'): protected_file(ROOT / name, private=True)
    # current is the sole intentional symlink. Its closed release namespace and
    # every descendant are protected before any carried play copies into them.
    for tree in (HELPERS, CONF, OPT, *dropins):
        if not tree.exists(): continue
        pending = [tree]
        while pending:
            directory = pending.pop()
            protected_directory(directory)
            for path in directory.iterdir():
                info = path.lstat()
                if path == HELPERS / 'current':
                    require(stat.S_ISLNK(info.st_mode) and info.st_uid == ROOT_UID,
                            'unsafe BSC current release pointer')
                    target = Path(os.readlink(path))
                    if not target.is_absolute(): target = HELPERS / target
                    require(target.parent == HELPERS / 'releases' and re.fullmatch('[a-f0-9]{64}', target.name),
                            'BSC current pointer leaves the release namespace')
                    protected_directory(target)
                    require(target.is_dir(), 'BSC current release is missing')
                elif stat.S_ISDIR(info.st_mode): pending.append(path)
                else: protected_file(path, missing=False)


def verify_publication():
    protected_paths()
    pointer = HELPERS / 'current'
    require(pointer.is_symlink(), 'BSC release publication is incomplete')
    target = Path(os.readlink(pointer))
    if not target.is_absolute(): target = HELPERS / target
    digest = hashlib.sha256()
    source = Path(__file__).resolve().parent
    for name in ('control.py', 'bootstrap.py', 'validator.py', 'catalog.json'):
        installed = target / name
        protected_file(installed, missing=False)
        raw = (source / name).read_bytes()
        require(installed.read_bytes() == raw, 'BSC published helper differs from its sealed source')
        digest.update(raw)
    require(target.name == digest.hexdigest(), 'BSC published release identity differs')
    protected_file(LAUNCHER, missing=False)
    require(LAUNCHER.read_bytes() == (source / 'launcher.py').read_bytes(), 'BSC published launcher differs from its sealed source')
    return {'helpers': 'verified'}


def read_state():
    protected_paths()
    path = ROOT / 'owner.json'
    protected_file(path, private=True, missing=False)
    require(not ROOT.is_symlink() and path.is_file() and not path.is_symlink(), 'BSC ownership is missing or unsafe')
    state = json.loads(path.read_text()); validate(state)
    require(state.get('phase') in ('prepared', 'installing', 'installed', 'retired'), 'unknown BSC ownership state')
    return state


def save(state):
    protected_paths()
    bootstrap.durable_json(ROOT / 'owner.json', state)


def run(argv, timeout=120, allowed=(0,)):
    result = subprocess.run(argv, env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'}, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    require(result.returncode in allowed, 'BSC host operation failed; inspect its owned service journal')
    return result.stdout


def loaded(unit=UNIT):
    value = run(['systemctl', 'show', '--property=LoadState', '--value', unit], allowed=(0, 1)).strip()
    require(value in (b'loaded', b'not-found', b'masked'), 'cannot establish BSC unit state')
    return value != b'not-found'


def active(unit=UNIT):
    return run(['systemctl', 'is-active', unit], allowed=(0, 3, 4)).decode().strip()


def check(state, request):
    protected_paths()
    validate(request, pin_required=False)
    require(contract(state) == contract(request), 'BSC owner/network/role/retention mismatch; nothing changed')
    for path in (ROOT, ROOT / 'data', ROOT / 'data/geth', ROOT / 'data/geth/chaindata', ROOT / 'identity', CONF, OPT):
        require(not path.is_symlink(), 'unsafe BSC storage or configuration')


def capacity(state):
    data = ROOT / 'data'
    probe = data
    while not probe.exists(): probe = probe.parent
    allocated = 0
    for path in (data, ROOT / 'snapshot-stage', ROOT / 'snapshot-downloads', ROOT / 'downloads'):
        require(not path.is_symlink(), 'unsafe BSC capacity source')
        if path.is_dir():
            require(path.stat().st_dev == probe.stat().st_dev, 'BSC bootstrap data and cache require one provisioned filesystem')
            raw = run(['du', '-sx', '-B1', str(path)]).split()
            require(raw and raw[0].isdigit(), 'cannot establish BSC data allocation')
            allocated += int(raw[0])
    snapshot = catalog(state['network'])['snapshots'][state['snapshot']]
    budget = sum(file['estimated_bytes'] + 32_000_000 for file in snapshot['files']) * 2 + bootstrap.RESERVE
    minimum = max(bootstrap.RESERVE, budget - allocated)
    require(bootstrap.shutil.disk_usage(probe).free >= minimum, 'insufficient BSC bootstrap or operating headroom')
    return budget


def processes(state):
    """Find writers by the exact managed data argument, including orphan processes.

    A foreign executable claiming this data directory is an error, never a kill
    target. PID start times and pidfds prevent signaling a reused process ID.
    """
    found = []
    expected = '--datadir=' + str(ROOT / 'data')
    uid = state.get('service_uid')
    for entry in PROC.iterdir():
        if not entry.name.isdigit(): continue
        try:
            args = (entry / 'cmdline').read_bytes().split(b'\x00')
            separated = any(value == b'--datadir' and index + 1 < len(args) and args[index + 1] == str(ROOT / 'data').encode() for index,value in enumerate(args))
            if expected.encode() not in args and not separated: continue
            executable = Path(os.readlink(entry / 'exe'))
            require(uid is not None and entry.stat().st_uid == uid and executable.name == 'geth' and OPT in executable.parents, 'a foreign process claims the owned BSC datadir')
            version = executable.parent.parent.name
            profile = dict(state, version=version, commit=catalog(state['network'])['releases'].get(version, {}).get('commit'))
            validate(profile)
            require(executable == binary(profile), 'unexpected BSC process executable')
            require(bootstrap.digest(executable, 'sha256') == release(profile)['binaries'][state['platform']]['sha256'], 'BSC process image differs from its reviewed digest')
            start = (entry / 'stat').read_text().rsplit(')', 1)[1].split()[19]
            found.append((int(entry.name), start))
        except (FileNotFoundError, ProcessLookupError):
            require(not entry.exists(), 'cannot establish whether a disappearing BSC process still owns its data')
            continue
    return found


def stop(state):
    if state['role']=='validator':
        for unit in ('erpc-bsc-activation.timer','erpc-bsc-activation.service'):
            if loaded(unit):
                run(['systemctl','stop',unit],timeout=120)
                require(active(unit) in ('inactive','failed','unknown'), 'BSC activation observer did not stop')
    if state.get('service_uid') is not None: account(state)
    if loaded():
        run(['systemctl', 'stop', UNIT], timeout=1860)
        require(active() in ('inactive', 'failed', 'unknown'), 'BSC service has not stopped')
        require(run(['systemctl', 'show', '--property=MainPID', '--value', UNIT]).strip() in (b'0', b''), 'BSC service still has a process')
    quiesce_writers(state)
    if state['role']=='validator' and state.get('journal_bound'):
        state['journal_checkpoint']=validator.journal(SimpleNamespace(**globals()),state);save(state)


def cancel_and_stop(state, retire=False):
    # Persistence and shutdown are independent attempts. A full/read-only
    # filesystem must not leave an already-owned node running indefinitely.
    state.update(deploy_intent=None, deploy_target=None, startup_revoked=True)
    if retire:state['phase']='retired'
    failures=[]
    try:save(state)
    except Exception:failures.append('cancellation storage')
    try:stop(state)
    except Exception:
        failures.append('shutdown or checkpoint storage')
        # A failed observer/unit stop must still attempt only revalidated owned
        # writers. This helper never signals a process with ambiguous ownership.
        try:quiesce_writers(state)
        except Exception:failures.append('owned writer drain')
    if failures:
        # A transient first write may recover after drain. Preserve cancellation
        # and the latest known checkpoint, but still report the failed operation.
        try:save(state)
        except Exception:failures.append('post-shutdown storage')
    units=[UNIT]
    if state['role']=='validator':units.append('erpc-bsc-activation.timer')
    for name in units:
        try:
            if loaded(name):run(['systemctl','disable',name])
        except Exception:failures.append('unit disable')
    if failures:
        raise Refused('BSC stop encountered '+', '.join(failures)+'; owned shutdown was attempted, repair storage/services and retry') from None
    return {'phase':state['phase'],'data_preserved':True}


def quiesce_writers(state):
    """Signal only reviewed writers, without stopping the calling observer unit."""
    for pid, start in processes(state):
        try:
            fd = os.pidfd_open(pid)
        except ProcessLookupError: continue
        try:
            current = PROC / str(pid)
            try: same = current.joinpath('stat').read_text().rsplit(')', 1)[1].split()[19] == start
            except FileNotFoundError: continue
            require(same, 'BSC process identity changed during stop')
            signal.pidfd_send_signal(fd, signal.SIGTERM)
            import select
            ready, _, _ = select.select([fd], [], [], 1800)
            require(ready, 'orphan BSC process did not stop gracefully')
        finally: os.close(fd)
    require(not processes(state), 'BSC datadir still has a writer')


def firewall_controller():
    import runpy
    protected_paths()
    path=HELPERS.parent/'rpc-firewall.py'
    protected_file(path,missing=False)
    return runpy.run_path(str(path),run_name='erpc_bsc_firewall')['Firewall']('bsc')


def firewall(state):
    receipt = state.get('firewall')
    require(isinstance(receipt, dict) and set(receipt) == {'run', 'bundle'} and
            isinstance(receipt['run'], str) and re.fullmatch('[a-z0-9-]{1,80}', receipt['run']) and
            isinstance(receipt['bundle'], str) and re.fullmatch('[a-f0-9]{64}', receipt['bundle']), 'BSC firewall receipt is missing or invalid')
    firewall_controller().dispatch('require-confirmed', receipt['run'], receipt['bundle'])


def artifacts(state):
    for path, digest in ((binary(state), release(state)['binaries'][state['platform']]['sha256']),
                         (CONF / 'config.toml', release(state)['config_sha256']),
                         (CONF / 'genesis.json', release(state)['genesis_sha256'])):
        require(path.is_file() and not path.is_symlink() and bootstrap.digest(path, 'sha256') == digest, 'BSC artifact differs from its reviewed pin')
    if state['role']=='validator':
        path=CONF/'validator.toml'
        require(path.is_file() and not path.is_symlink() and path.read_bytes()==validator.configuration(SimpleNamespace(**globals()),state), 'validator listener configuration differs')
    identity = ROOT / 'identity/nodekey'
    require(identity.is_file() and not identity.is_symlink() and bootstrap.digest(identity, 'sha256') == state.get('identity_sha256'), 'BSC identity is missing or changed; recovery required')


def account(state):
    uid,gid=state.get('service_uid'),state.get('service_gid')
    require(all(type(value) is int and 100 <= value <= 65534 for value in (uid,gid)), 'invalid BSC service identity')
    actual=pwd.getpwnam(ACCOUNT)
    require(actual.pw_uid == uid and actual.pw_gid == gid, 'BSC service account changed; explicit recovery required')


def release_supported(state, now=None):
    upgrade=catalog(state['network']).get('network_upgrade')
    if upgrade is None:return True
    current=time.time() if now is None else now
    return current < upgrade['activation_unix'] or tuple(map(int,state['version'].split('.'))) >= tuple(map(int,upgrade['minimum_version'].split('.')))


def guard(state):
    check(state, state)
    require(not state.get('startup_revoked') and state['phase'] == 'installed' and state.get('installed') == pin(state), 'BSC installation is fenced or retired')
    require(release_supported(state), 'BSC mainnet Jenner requires an explicit update to 1.8.2 or a later qualified release')
    account(state); capacity(state); artifacts(state); firewall(state)
    if state['role']=='validator':validator.guard(SimpleNamespace(**globals()),state)
    receipt = ROOT / 'bootstrap.json'
    require(receipt.is_file() and json.loads(receipt.read_text()).get('phase') == 'complete', 'BSC bootstrap is incomplete')


def arguments(state):
    history = '0' if state['storage'] == 'full' else '600000'
    return [str(binary(state)), '--' + state['network'], '--config=' + str(CONF / 'config.toml'),
            '--datadir=' + str(ROOT / 'data'), '--nodekey=' + str(ROOT / 'identity/nodekey'),
            '--keystore=' + str(CONF / 'empty-keystore'), '--syncmode=full', '--state.scheme=path', '--db.engine=pebble',
            '--tries-verify-mode=local', '--history.blocks=' + history, '--history.transactions=' + history,
            '--history.logs=600000', '--cache=10000', '--port=30311', '--maxpeers=200',
            '--http', '--http.addr=127.0.0.1', '--http.port=8545', '--http.api=eth,net,web3', '--http.vhosts=localhost',
            '--ws', '--ws.addr=127.0.0.1', '--ws.port=8546', '--ws.api=eth,net,web3', '--ws.origins=localhost',
            '--metrics', '--metrics.addr=127.0.0.1', '--metrics.port=6060',
            '--mine=false', '--vote=false', '--allow-insecure-unlock=false', '--rpc.allow-unprotected-txs=false']


def execute(state):
    guard(state)
    require(not processes(state), 'owned BSC database already has a writer')
    uid, gid = state.get('service_uid'), state.get('service_gid')
    require(all(type(value) is int and 100 <= value <= 65534 for value in (uid, gid)), 'invalid BSC service identity')
    argv = arguments(state)
    if state['role']=='validator':
        validator.journal(SimpleNamespace(**globals()),state)
        argv,_ = validator.runtime_arguments(SimpleNamespace(**globals()),state,argv)
    os.setgroups([]); os.setgid(gid); os.setuid(uid)
    os.execve(argv[0], argv, {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})


def prepare(request):
    validate(request)
    protected_paths()
    if (ROOT / 'owner.json').exists():
        state = read_state(); check(state, request)
        require(state['phase'] == 'prepared' and pin(state) == pin(request), 'BSC host already initialized; use deploy to resume')
        capacity(state); return {'phase': 'prepared'}
    # Without the durable owner, even unpublished identity/bootstrap remnants
    # cannot be distinguished from another node's state. Never adopt them.
    require(not ROOT.exists() or (ROOT.is_dir() and not any(ROOT.iterdir())), 'unowned BSC state or staged identity cannot be adopted')
    for path in (CONF, OPT, HELPERS, LAUNCHER, *[UNIT_DIRECTORY / name for name in owned_units()],
                 *[UNIT_DIRECTORY / (name + '.d') for name in owned_units()]):
        require(not path.exists() and not path.is_symlink(), 'unowned BSC managed artifacts cannot be adopted')
    require(not loaded(), 'unowned BSC service cannot be adopted')
    for lookup in (pwd.getpwnam, grp.getgrnam):
        try: lookup(ACCOUNT)
        except KeyError: pass
        else: raise Refused('unowned BSC service account or group exists')
    state = dict(contract(request), **pin(request), phase='prepared')
    capacity(state)
    require(not processes(state), 'existing BSC process cannot be adopted')
    ROOT.mkdir(mode=0o755, parents=True, exist_ok=True)
    # An already verified root-owned directory may be made traversable; unsafe
    # ownership/modes were refused above, never repaired into trusted state.
    ROOT.chmod(0o755)
    save(state)
    return {'phase': 'prepared'}


def install(state, request):
    require(state['phase'] == 'installing' and state['target'] == pin(request), 'BSC installation target differs')
    require(not processes(state), 'BSC datadir is still in use')
    capacity(state)
    uid, gid = request.get('service_uid'), request.get('service_gid')
    require(all(type(v) is int and 100 <= v <= 65534 for v in (uid, gid)), 'invalid BSC service identity')
    require(state.get('service_uid',uid) == uid and state.get('service_gid',gid) == gid, 'BSC service identity changed; recovery required')
    state.update(service_uid=uid,service_gid=gid); save(state)
    selected = release(request); cache = ROOT / 'downloads'
    cache.mkdir(mode=0o700, exist_ok=True)
    for path in (cache, OPT, OPT / request['version'], binary(request).parent, CONF, ROOT / 'identity'):
        require(not path.is_symlink(), 'unsafe BSC install destination'); path.mkdir(mode=0o755, parents=True, exist_ok=True)
        path.chmod(0o700 if path == cache else 0o755)
    asset = selected['binaries'][state['platform']]
    source = bootstrap.download(asset['url'], cache / ('geth-' + request['version'] + '-' + state['platform']), asset['sha256'], 'sha256', asset['size'])
    temporary = binary(request).with_suffix('.new')
    require(not temporary.is_symlink() and not binary(request).is_symlink(), 'unsafe binary destination')
    bootstrap.shutil.copyfile(source, temporary); temporary.chmod(0o755); os.replace(temporary, binary(request))
    metadata = selected['network_zip']
    archive = bootstrap.download(metadata['url'], cache / ('network-' + request['version'] + '.zip'), metadata['sha256'], 'sha256', metadata['size'])
    prefix = 'mainnet' if state['network'] == 'mainnet' else 'testnet'
    with zipfile.ZipFile(archive) as package:
        for name, expected in [('genesis.json', selected['genesis_sha256']), ('config.toml', selected['config_sha256'])]:
            member = package.getinfo(prefix + '/' + name)
            require(member.file_size <= 2_000_000, 'oversized network metadata')
            raw = package.read(member)
            require(hashlib.sha256(raw).hexdigest() == expected, 'network metadata differs from pinned bytes')
            path = CONF / name; require(not path.is_symlink(), 'unsafe configuration destination')
            path.write_bytes(raw); path.chmod(0o644)
    if state['role']=='validator':validator.write_configuration(SimpleNamespace(**globals()),request)
    identity = ROOT / 'identity/nodekey'
    temporary_identity = identity.with_suffix('.new')
    require(not identity.is_symlink() and not temporary_identity.is_symlink(), 'unsafe BSC identity destination')
    if not state.get('identity_sha256'):
        require(not identity.exists(), 'unowned BSC identity cannot be adopted')
        # P2P identity only; this does not create a validator or funded account.
        order = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
        if temporary_identity.exists():
            raw = temporary_identity.read_bytes()
            require(re.fullmatch(b'[0-9a-f]{64}',raw) and 0 < int(raw,16) < order,
                    'interrupted BSC identity staging is invalid')
        else:
            raw = (secrets.randbelow(order - 1) + 1).to_bytes(32, 'big').hex().encode()
            fd = os.open(temporary_identity, os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_WRONLY, 0o600)
            with os.fdopen(fd, 'wb') as stream: stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        # The staged name must survive a crash before its hash becomes authoritative.
        fd = os.open(identity.parent, os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)
        state['identity_sha256'] = hashlib.sha256(raw).hexdigest(); save(state)
    if not identity.exists() and temporary_identity.is_file():
        require(bootstrap.digest(temporary_identity,'sha256') == state['identity_sha256'], 'staged identity differs from its owner')
        os.replace(temporary_identity,identity)
        fd = os.open(identity.parent,os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)
    require(identity.is_file() and bootstrap.digest(identity,'sha256') == state['identity_sha256'], 'BSC identity recovery required')
    os.chown(identity,uid,gid)
    empty = CONF / 'empty-keystore'; require(not empty.is_symlink(), 'unsafe keystore boundary')
    empty.mkdir(mode=0o555, exist_ok=True); require(not any(empty.iterdir()), 'RPC nodes cannot adopt account keys')
    snapshot = catalog(state['network'])['snapshots'][state['snapshot']]
    bootstrap.bootstrap(ROOT, state['owner'], snapshot, uid, gid, capacity(state))
    os.chown(ROOT / 'data', uid, gid)
    run(['runuser', '-u', ACCOUNT, '--', str(binary(request)), '--datadir=' + str(ROOT / 'data'),
         '--state.scheme=path', '--db.engine=pebble', 'init', str(CONF / 'genesis.json')], timeout=600)
    state.update(service_uid=uid, service_gid=gid); save(state)
    if state['role']=='validator':
        validator.provision(SimpleNamespace(**globals()),state)
        validator.journal(SimpleNamespace(**globals()),state,initialize=True)
    return {'artifacts': 'verified', 'bootstrap': 'complete'}


def rpc(method, params=None, *, expected=None):
    require(method in ('eth_chainId', 'eth_getBlockByNumber', 'eth_syncing', 'net_peerCount', 'admin_nodeInfo', 'eth_call', 'eth_mining', 'miner_start', 'miner_stop', 'parlia_getSnapshotAtHash'), 'unsupported BSC inspection method')
    path = ROOT / 'data/geth.ipc'
    require(path.exists() and not path.is_symlink(), 'private BSC inspection socket unavailable')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(10); client.connect(str(path))
        if expected is not None:
            pid,start,uid=expected
            actual=struct.unpack('3i',client.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            require((actual[0],actual[1])==(pid,uid), 'BSC IPC peer differs from the owned signer')
            require((PROC/str(pid)/'stat').read_text().rsplit(')',1)[1].split()[19]==start, 'BSC IPC process identity changed')
        client.sendall(json.dumps({'jsonrpc':'2.0', 'id':1, 'method':method, 'params':params or []}).encode() + b'\n')
        raw = bytearray()
        while len(raw) <= 1_048_576:
            chunk = client.recv(65536)
            require(chunk, 'BSC inspection response ended early'); raw.extend(chunk)
            try: response = json.loads(raw)
            except json.JSONDecodeError: continue
            require(response.get('id') == 1 and response.get('jsonrpc') == '2.0' and 'result' in response and 'error' not in response, 'BSC inspection failed')
            return response['result']
    raise Refused('BSC inspection response exceeded bound')


def clock_synchronized():
    try:
        value=run(['/usr/bin/timedatectl','show','-p','NTPSynchronized','--value']).strip()
        require(value in (b'yes',b'no'), 'clock synchronization state unavailable')
        return value==b'yes'
    except Exception:return None


def status(state, peer=None):
    result = {'phase':state['phase'], 'network':state['network'], 'storage':state['storage'], 'service':active(), 'ready':False,
              'installed':state.get('installed'), 'target':state.get('target'), 'role':state['role'],
              'release_supported':release_supported(state),'recommended_version':catalog(state['network'])['recommended'],
              'network_upgrade':catalog(state['network']).get('network_upgrade')}
    if state['role']=='validator':
        result.update(identities=validator.public(state),backup_confirmed=state.get('backup_confirmed') is True,clock_synchronized=clock_synchronized())
    try:
        inspect=rpc if peer is None else lambda method,params=None:rpc(method,params,expected=peer)
        guard(state)
        writers = processes(state)
        require(len(writers) == 1, 'owned BSC writer unavailable')
        pid = run(['systemctl', 'show', '--property=MainPID', '--value', UNIT]).strip()
        require(pid.isdigit() and int(pid) == writers[0][0], 'BSC service does not own its database process')
        profile = catalog(state['network'])
        require(inspect('eth_chainId') == hex(profile['chain_id']), 'BSC chain identity differs')
        require(inspect('eth_getBlockByNumber', ['0x0',False]).get('hash') == profile['genesis_hash'], 'BSC genesis identity differs')
        latest = inspect('eth_getBlockByNumber', ['latest',False])
        require(isinstance(latest, dict) and all(isinstance(latest.get(k), str) and re.fullmatch('0x[0-9a-fA-F]{1,16}',latest[k]) for k in ('number','timestamp')), 'BSC head response malformed')
        peers = inspect('net_peerCount'); require(isinstance(peers,str) and re.fullmatch('0x[0-9a-fA-F]{1,8}',peers), 'BSC peer count unavailable')
        age = int(time.time()) - int(latest['timestamp'],16)
        identity=inspect('admin_nodeInfo')
        require(isinstance(identity,dict) and isinstance(identity.get('id'),str) and re.fullmatch('[a-fA-F0-9]{64}',identity['id']), 'BSC peer identity unavailable')
        syncing = inspect('eth_syncing')
        result.update(peer_id=identity['id'],block=latest['number'], block_age_seconds=age, peers=int(peers,16), syncing=syncing)
        result['ready'] = result['service'] == 'active' and syncing is False and int(peers,16) > 0 and -120 <= age <= 120
        if state['role']=='validator':
            context=SimpleNamespace(**dict(globals(),rpc=inspect))
            epoch=validator.election(context,state,latest)
            registration=validator.registration(context,state,{'blockHash':latest['hash'],'requireCanonical':True})
            mining=inspect('eth_mining');require(type(mining)is bool,'BSC mining state unavailable')
            result.update(registration=registration,mining=mining,epoch=epoch)
            result['node_ready']=result['ready']
            result['validator_eligible']=result['ready'] and result['clock_synchronized'] is True and registration['registered'] and not registration['jailed'] and mining and state.get('backup_confirmed') is True
            result['ready']=result['validator_eligible'] and epoch['consensus_elected'] and epoch['vote_elected']
    except Exception:
        result['ready']=False
        result['inspection_error'] = 'owned process, network, freshness or synchronization unavailable'
    return result


def signer_peer(state):
    """Establish control authority independently from signing eligibility."""
    writers=processes(state)
    require(len(writers)==1 and type(state.get('service_uid'))is int,'owned signer process unavailable')
    pid,start=writers[0]
    require(run(['systemctl','show','--property=MainPID','--value',UNIT]).strip()==str(pid).encode(),'service does not own this signer')
    peer=(pid,start,state['service_uid']);profile=catalog(state['network'])
    require(rpc('eth_chainId',expected=peer)==hex(profile['chain_id']),'owned signer network differs')
    genesis=rpc('eth_getBlockByNumber',['0x0',False],expected=peer)
    require(isinstance(genesis,dict) and genesis.get('hash')==profile['genesis_hash'],'owned signer genesis differs')
    return peer


def fence_validator(state):
    # Never clear an interrupted target or rewrite original data/custody. A
    # failed prior drain still needs this path even after startup was revoked.
    state.update(startup_revoked=True,deploy_intent=None,deploy_target=None)
    try:save(state)
    except Exception:
        # Full/read-only storage must not skip stopping an existing signer.
        # Queue shutdown without waiting on this observer's own Requires= job.
        try:run(['systemctl','stop','--no-block','erpc-bsc-activation.timer',UNIT])
        finally:quiesce_writers(state)
        raise Refused('cannot persist validator fence; owned writer stopped, repair storage before restart') from None
    quiesce_writers(state)
    raise Refused('validator observation failed; owned signing fenced and stopped') from None


def activate(state):
    if not release_supported(state):return fence_validator(state)
    require(state['phase']=='installed' and state.get('startup_revoked')is False,'observer cannot activate a fenced installation')
    try:
        peer=signer_peer(state)
        try:
            guard(state);observed=status(state,peer)
            eligible='inspection_error' not in observed and observed.get('clock_synchronized') is True and observed.get('node_ready') is True and observed.get('registration',{}).get('registered') is True and observed.get('registration',{}).get('jailed') is False and state.get('backup_confirmed') is True
        except Exception:eligible=False
        rpc('miner_start' if eligible else 'miner_stop',expected=peer)
        if not eligible:require(rpc('eth_mining',expected=peer)is False,'owned signer did not confirm mining stopped')
        return {'eligible':eligible}
    except Exception:
        return fence_validator(state)


def deploy_intent(request):
    value = request.get('intent')
    require(isinstance(value, str) and re.fullmatch('[a-f0-9]{32}', value), 'invalid BSC deployment intent')
    return value


def check_deploy(state, request):
    require(state.get('deploy_intent') == deploy_intent(request) and state.get('deploy_target') == pin(request), 'BSC deployment was cancelled or superseded')


def dispatch(state, request):
    check(state, request)
    action = request.get('action')
    if action == 'status': return status(state)
    if action == 'verify-helpers': return verify_publication()
    if action in ('export-custody','confirm-backup','restore-custody'):
        require(state['role']=='validator','custody is only a validator operation')
        if action=='export-custody':return validator.export_backup(SimpleNamespace(**globals()),state)
        if action=='confirm-backup':
            validator.confirm_backup(SimpleNamespace(**globals()),state,request.get('backup_digest'));return {'backup_confirmed':True}
        state.update(startup_revoked=True,deploy_intent=None,deploy_target=None);save(state);stop(state)
        validator.restore(SimpleNamespace(**globals()),state,request.get('backup'))
        return {'custody':'recovered','service':'stopped','journal':'preserved'}
    if action == 'activate':
        require(state['role']=='validator','activation is only a validator operation')
        return activate(state)
    if action == 'authorize-deploy':
        target = target_pin(request)
        if 'target' in state: require(state['target'] == target, 'resume the existing BSC target first')
        state.update(deploy_intent=deploy_intent(request), deploy_target=target); save(state)
        return {'authorized': True}
    if action in ('check-deploy', 'begin-install', 'install-artifacts', 'finish-install'):
        check_deploy(state, request)
    if action == 'check-deploy': return {'authorized': True}
    if action == 'begin-install':
        target = pin(request); capacity(state)
        previous = state.get('installed',pin(state))['version']
        require(tuple(map(int,target['version'].split('.'))) >= tuple(map(int,previous.split('.'))), 'BSC database downgrades are refused')
        if 'target' in state: require(state['target'] == target, 'resume the existing BSC target first')
        state.update(phase='installing',target=target,startup_revoked=True); save(state); stop(state)
        return {'phase':'installing'}
    if action == 'install-artifacts': return install(state,request)
    if action == 'finish-install':
        require(state['phase'] == 'installing' and state['target'] == pin(request), 'BSC installation target differs')
        require(not processes(state), 'BSC writer is still active during installation')
        candidate=dict(state); candidate.update(**pin(request), firewall=request['firewall'], installed=pin(request), phase='installed', startup_revoked=False)
        candidate.pop('target',None); guard(candidate); save(candidate)
        return {'phase':'installed'}
    if action in ('start','restart'):
        require(pin(request) == state.get('installed'), 'inventory differs from installed BSC configuration')
        if 'intent' in request: check_deploy(state, request)
        else:
            # An explicit operator start/restart supersedes any queued deployment.
            state.update(deploy_intent=None, deploy_target=None)
        candidate=dict(state, startup_revoked=False); guard(candidate)
        if action == 'restart':
            state['startup_revoked']=True; save(state); stop(state)
        state=candidate; save(state)
        run(['systemctl','enable',UNIT]); run(['systemctl','start',UNIT],timeout=240)
        if state['role']=='validator':
            run(['systemctl','enable','--now','erpc-bsc-activation.timer'])
        require(active() == 'active','BSC service did not start')
        state.update(deploy_intent=None, deploy_target=None); save(state)
        return status(state)
    if action in ('stop','destroy'):
        return cancel_and_stop(state, retire=action=='destroy')
    raise Refused('unsupported BSC operation')


def locked(request, in_play=False):
    operation = None
    contended = False
    if not in_play and request.get('action') != 'status':
        operation = os.open(OPERATION_ROOT,os.O_RDONLY)
        try: fcntl.flock(operation,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(operation);operation=None
            require(request.get('action')=='activate', 'another node operation is running')
            contended=True
        except Exception:
            os.close(operation); raise Refused('another node operation is running') from None
    try:
        fd = os.open(LOCK,os.O_CREAT|os.O_NOFOLLOW|os.O_RDWR,0o600)
        with os.fdopen(fd,'w') as stream:
            fcntl.flock(stream,fcntl.LOCK_EX)
            if contended:
                # The shared run may still be installing Ansible and has not
                # yet fenced BSC. Under the same BSC lock, re-read the original
                # state and allow ONLY expiry cancellation/drain, never mining.
                state=read_state();check(state,request)
                require(state['role']=='validator' and not release_supported(state), 'another node operation is running')
                return fence_validator(state)
            return prepare(request) if request.get('action') == 'prepare' else dispatch(read_state(),request)
    finally:
        if operation is not None: os.close(operation)


def main():
    os.umask(0o077)
    import resource
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    require(os.geteuid() == 0,'root is required')
    if sys.argv[1:] == ['firewall-load']:
        read_state();firewall_controller().dispatch('load');return
    if len(sys.argv)==4 and sys.argv[1] in ('firewall-confirm','firewall-apply','firewall-require'):
        read_state()
        action={'firewall-confirm':'confirm','firewall-apply':'apply','firewall-require':'require-confirmed'}[sys.argv[1]]
        firewall_controller().dispatch(action,*sys.argv[2:]);return
    if sys.argv[1:] == ['guard']: guard(read_state()); return
    if sys.argv[1:] == ['execute']: execute(read_state()); return
    if sys.argv[1:] == ['activate']:
        state=read_state();state['action']='activate';print(json.dumps(locked(state)));return
    require(sys.argv[1:] in ([],['play']),'unsupported BSC controller invocation')
    raw = sys.stdin.buffer.read(262145); require(len(raw) <= 262144,'BSC request too large')
    request=json.loads(raw);result=locked(request,in_play=sys.argv[1:] == ['play'])
    print(result if request.get('action')=='export-custody' else json.dumps(result))


if __name__ == '__main__':
    try:
        load_dependencies()
        main()
    except Refused as error:
        print(str(error),file=sys.stderr);sys.exit(1)
    except Exception:
        print('BSC operation failed; data and ownership retained',file=sys.stderr);sys.exit(1)
