#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Dedicated Nitro follower: persistent ownership before every host mutation."""
import fcntl
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
import time
import urllib.request

ROOT = Path('/var/lib/erpc-nitro')
TRUST_ANCHOR = Path('/')
ROOT_UID = 0
NAMESPACE = Path('/usr/local/lib/erpc')
CONF = Path('/etc/erpc/nitro')
LOCK = Path('/run/lock/erpc-nitro.lock')
OPERATION_ROOT = Path('/opt/erpc')
DOCKER = ['/usr/bin/docker', '--host=unix:///var/run/docker.sock']
VERSION = '3.12.1'
COMMIT = '70fa99a6e711f09eedd96a907290c3df0f3bcf7d'
IMAGES = {
    'amd64': 'sha256:948cf8c42a6ed85bc055f13866fb9a029c8234dc16c12d7ffa4ed669270aaea8',
    'arm64': 'sha256:b285195fcd048005d0530e87f827e9b0e506e730fd7822a6ee4ac17c93b87b32',
}
RELEASES = {VERSION: {'commit': COMMIT, 'images': IMAGES}}
NETWORKS = {
    ('arbitrum', 'mainnet'): (42161, 'mainnet', 'arb1', 6_000),
    ('arbitrum', 'nova'): (42170, 'mainnet', 'nova', 2_000),
    ('arbitrum', 'sepolia'): (421614, 'sepolia', 'sepolia-rollup', 2_000),
    ('robinhood', 'mainnet'): (4663, 'mainnet', 'Robinhood Chain', 2_000),
    ('robinhood', 'testnet'): (46630, 'sepolia', 'Robinhood Chain Sepolia', 2_000),
}
INFO_HASH = {
    'arbitrum': 'd7e8b87f078b10178a0ef03e809d3dad93a2583f6e181cc50f12368b57e58cdc',
    'mainnet': 'cf6c0aa2bc520a28fe8983f783676bc43de94cc25a57a1cdc9b1f0afc5208f0a',
    'testnet': '0ad167c746c2aa9169c84a252f8c863140cdbd4fc23b571fa1041f94cabaf745',
}
GENESIS_HASH = '353e6f6441b47695b41cee0c3645cde8dd7492d2f7f574bfb6aa4371e41bb6ba'


class Refused(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Refused(message)


def network(state):
    return NETWORKS[(state['family'], state['network'])]


def validate(request, release_required=True):
    require(isinstance(request, dict), 'invalid Nitro request')
    require((request.get('family'), request.get('network')) in NETWORKS, 'unsupported Nitro network')
    require(isinstance(request.get('owner'), str) and re.fullmatch('[a-z0-9]{1,80}', request['owner']), 'invalid owner')
    require(isinstance(request.get('config_id'), str) and re.fullmatch('[a-f0-9]{64}', request['config_id']), 'invalid Nitro configuration identity')
    require(request.get('platform') in ('amd64', 'arm64'), 'unsupported image architecture')
    if release_required:
        release = RELEASES.get(request.get('version'))
        require(release is not None and request.get('commit') == release['commit'], 'unreviewed Nitro release; update erpc release catalog')
        require(request['platform'] in release['images'], 'release is not qualified for this platform')


def contract(request):
    return {key: request[key] for key in ('owner', 'family', 'network', 'platform')}


def pin(request):
    validate(request)
    return {'version': request['version'], 'commit': request['commit'], 'image': RELEASES[request['version']]['images'][request['platform']], 'config_id': request['config_id']}


def unit(state, component='nitro'):
    return 'erpc-' + state['family'] + '-' + component


def run(argv, *, input=None, allowed=(0,), timeout=120):
    environment = docker_environment() if argv and argv[0] == DOCKER[0] else None
    result = subprocess.run(argv, input=input, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout, check=False, env=environment)
    require(result.returncode in allowed, 'Nitro host operation failed; inspect the owned service journal')
    return result.stdout


def docker_environment():
    # Operator Docker contexts/environment must not redirect this host's owned
    # lifecycle to another daemon. Registry authentication stays Docker-managed.
    return {key: value for key, value in os.environ.items() if not key.startswith('DOCKER_')}


def loaded(name):
    result = run(['systemctl', 'show', '--property=LoadState', '--value', name], allowed=(0, 1)).strip()
    require(result in (b'loaded', b'not-found', b'masked'), 'cannot establish service ownership')
    return result != b'not-found'


def active(name):
    return run(['systemctl', 'is-active', name], allowed=(0, 3, 4)).decode().strip()


def protected_directory(path, missing=False):
    current = TRUST_ANCHOR
    require(path.is_absolute() and os.path.normpath(path) == str(path), 'invalid protected Nitro directory')
    for part in (None, *path.relative_to(TRUST_ANCHOR).parts):
        if part is not None:
            current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            require(missing, 'protected Nitro ancestor is missing')
            continue
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == ROOT_UID and info.st_mode & 0o022 == 0,
                'Nitro state and helpers require protected real root-owned ancestors')


def protected_root():
    protected_directory(ROOT, missing=True)


def control_destination(expected=None):
    # A sealed upload does not make an existing installed namespace trustworthy.
    # Only the final erpc directory may be absent; never adopt an unsafe parent.
    protected_directory(NAMESPACE.parent)
    protected_directory(NAMESPACE, missing=True)
    pending = [NAMESPACE] if NAMESPACE.exists() else []
    while pending:
        with os.scandir(pending.pop()) as children:
            for child in children:
                info = child.stat(follow_symlinks=False)
                require(info.st_uid == ROOT_UID and info.st_mode & 0o022 == 0,
                        'installed Nitro helper namespace contains untrusted content')
                if stat.S_ISDIR(info.st_mode):
                    pending.append(Path(child.path))
                else:
                    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                            'installed Nitro helpers cannot be links or special files')
    path = NAMESPACE / 'nitro-control'
    try:
        info = path.lstat()
    except FileNotFoundError:
        require(expected is None, 'published Nitro controller is missing')
        return
    require(stat.S_ISREG(info.st_mode) and info.st_uid == ROOT_UID and
            info.st_mode & 0o022 == 0 and info.st_nlink == 1,
            'installed Nitro controller is not a protected ordinary file')
    if expected is not None:
        require(info.st_size <= 256 * 1024 and hashlib.sha256(path.read_bytes()).hexdigest() == expected,
                'published Nitro controller differs from the sealed carried source')


def state_read():
    protected_root()
    path = ROOT / 'owner.json'
    require(not ROOT.is_symlink() and path.is_file() and not path.is_symlink(), 'Nitro ownership missing or unsafe')
    info = path.stat()
    require(info.st_uid == ROOT_UID and info.st_mode & 0o077 == 0 and info.st_nlink == 1 and info.st_size <= 65536, 'unsafe Nitro ownership file')
    state = json.loads(path.read_text())
    validate(state)
    if isinstance(state.get('phase'), str) and state['phase'].startswith('v2:'):
        require(state.get('lifecycle_schema') == 2, 'incomplete Nitro lifecycle migration')
        state['phase'] = state['phase'][3:]
    elif 'lifecycle_schema' in state:
        raise Refused('invalid Nitro lifecycle format')
    require(type(state.get('generation', 0)) is int and 0 <= state.get('generation', 0) < 2**63, 'invalid Nitro cancellation generation')
    require(state.get('phase') in ('prepared', 'installing', 'installed', 'retired'), 'unknown Nitro ownership format')
    return state


def save(state):
    protected_root()
    temporary = ROOT / 'owner.new'
    require(not temporary.is_symlink(), 'unsafe ownership file')
    temporary.unlink(missing_ok=True)
    fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w') as stream:
        # Old carried/installed helpers reject this phase before mutation. They
        # cannot silently erase a stop fence or restart a cancelled deployment.
        stored = dict(state, lifecycle_schema=2, phase='v2:' + state['phase'])
        json.dump(stored, stream)
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
        require(not Path('/var/lib/docker/containers').exists(), 'uninspected Docker state requires operator recovery')
        return
    name = unit(state)
    listed = run([*DOCKER, 'container', 'ls', '--all', '--format', '{{.Names}}', '--filter', 'name=^/' + name + '$']).decode().splitlines()
    if not listed:
        return
    require(listed == [name], 'unexpected Nitro container identity')
    raw = run([*DOCKER, 'container', 'inspect', name])
    require(len(raw) <= 1024 * 1024, 'oversized container inspection')
    result = json.loads(raw)
    require(isinstance(result, list) and len(result) == 1, 'ambiguous Nitro container ownership')
    labels = result[0].get('Config', {}).get('Labels', {}) or {}
    require(all(labels.get('erpc.' + key) == state[key] for key in ('owner', 'family', 'network')),
            'an unowned Nitro container exists; nothing stopped or replaced')
    return result[0]


def check(state, request):
    validate(request, release_required=False)
    require(contract(state) == contract(request), 'Nitro owner/network/platform mismatch; nothing changed')
    require(not (ROOT / 'data').is_symlink() and not (ROOT / 'data/cache').is_symlink() and not CONF.is_symlink(), 'unsafe Nitro storage/configuration')
    check_container(state)


def capacity(state):
    data = ROOT / 'data'
    probe = data
    while not probe.exists():
        probe = probe.parent
    allocated = 0
    if data.is_dir():
        raw = run(['du', '-sx', '-B1', str(data)]).split()
        require(raw and raw[0].isdigit(), 'cannot measure Nitro storage')
        allocated = int(raw[0])
    # Source docs require room for snapshot plus extracted state. Keep a 200GB
    # operating reserve even after the initial deployment budget is allocated.
    minimum = max(200_000_000_000, network(state)[3] * 1_000_000_000 - allocated)
    require(shutil.disk_usage(probe).free >= minimum, 'insufficient Nitro bootstrap space or operating headroom')


def prepare(request):
    protected_root()
    validate(request)
    control_destination()
    require(not ROOT.is_symlink(), 'unsafe Nitro root')
    if (ROOT / 'owner.json').exists():
        state = state_read()
        check(state, request)
        require(state['phase'] == 'prepared', 'host already initialized; use deploy to resume or refresh it')
        require(pin(state) == pin(request), 'prepared host belongs to another desired configuration')
        capacity(state)
        return {'phase': state['phase']}
    for family in ('arbitrum', 'robinhood'):
        for component in ('nitro', 'upstreams'):
            require(not loaded('erpc-' + family + '-' + component), 'unowned Nitro service exists')
    require(not (ROOT / 'data').exists(), 'unowned Nitro data cannot be adopted')
    check_container(request)
    state = dict(contract(request), version=request['version'], commit=request['commit'], config_id=request['config_id'], phase='prepared', startup_revoked=True, generation=0)
    capacity(state)
    ROOT.mkdir(mode=0o755, parents=True, exist_ok=True)
    fd = os.open(ROOT.parent, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    save(state)
    return {'phase': 'prepared'}


def file_hash(path, expected):
    require(path.is_file() and not path.is_symlink() and hashlib.sha256(path.read_bytes()).hexdigest() == expected,
            'Nitro network artifact differs from the reviewed pin')


def artifacts(state):
    file_hash(CONF / 'chain-info.json', INFO_HASH['arbitrum' if state['family'] == 'arbitrum' else state['network']])
    if state['family'] == 'robinhood' and state['network'] == 'mainnet':
        file_hash(CONF / 'genesis.json', GENESIS_HASH)


def stop(state):
    for component in ('nitro', 'upstreams'):
        name = unit(state, component)
        if loaded(name):
            run(['systemctl', 'stop', name], timeout=1860)
            require(active(name) in ('inactive', 'failed', 'unknown'), 'Nitro service did not stop')
            require(run(['systemctl', 'show', '--property=MainPID', '--value', name]).strip() in (b'0', b''), 'Nitro service still has a process')
    # Docker can outlive a lost/inactive service unit. Service state alone is
    # insufficient before replacing artifacts or retiring this database owner.
    container = check_container(state)
    if container is not None:
        identity = container.get('Id')
        require(isinstance(identity, str) and re.fullmatch('[a-f0-9]{64}', identity), 'ambiguous container identity')
        running = container.get('State', {}).get('Running')
        require(type(running) is bool, 'container running state is unavailable')
        if running:
            run([*DOCKER, 'container', 'stop', '--time=1800', identity], timeout=1860)
        remaining = check_container(state)
        require(remaining is None or (remaining.get('Id') == identity and
                remaining.get('State', {}).get('Running') is False and
                remaining.get('State', {}).get('Pid') == 0),
                'owned Nitro container is still running or changed during stop')


def firewall(state):
    # Root-owned immutable receipt generated by the separate firewall-only run.
    receipt = state.get('firewall')
    require(isinstance(receipt, dict) and set(receipt) == {'run', 'bundle'}, 'confirmed firewall receipt missing')
    require(re.fullmatch('[a-z0-9-]{1,80}', receipt['run']) and re.fullmatch('[a-f0-9]{64}', receipt['bundle']), 'invalid firewall receipt')
    run(['/usr/bin/python3', '-I', '/usr/local/lib/erpc/rpc-firewall.py', state['family'], 'require-confirmed', receipt['run'], receipt['bundle']])


def guard(state):
    check(state, state)
    require(state['phase'] == 'installed' and state.get('installed') == pin(state), 'Nitro installation is incomplete or retired')
    require(state.get('startup_revoked', False) is False, 'Nitro startup is persistently revoked')
    capacity(state)
    artifacts(state)
    firewall(state)
    credential = CONF / 'l1-upstreams.cred'
    require(credential.is_file() and not credential.is_symlink(), 'encrypted L1 credentials are missing')


def arguments(state):
    chain_id, _, chain_name, _ = network(state)
    args = ['--persistent.global-config=/data', '--persistent.chain=/data/chain',
            '--chain.id=' + str(chain_id), '--chain.name=' + chain_name,
            '--chain.info-files=/config/chain-info.json',
            '--parent-chain.connection.url=http://127.0.0.1:18545',
            '--parent-chain.blob-client.beacon-url=http://127.0.0.1:15052',
            '--node.parent-chain-reader.poll-only=true',
            '--node.staker.enable=false', '--node.block-validator.enable=false',
            '--node.batch-poster.enable=false', '--execution.sequencer.enable=false',
            '--execution.caching.state-scheme=path', '--execution.caching.archive=false',
            '--execution.tx-indexer.tx-lookup-limit=0',
            '--http.addr=127.0.0.1', '--http.port=8547', '--http.api=eth,net,web3,arb',
            '--http.vhosts=localhost', '--ws.addr=127.0.0.1', '--ws.port=8548',
            '--ws.api=eth,net,web3,arb', '--ws.origins=localhost',
            '--metrics', '--metrics-server.addr=127.0.0.1', '--metrics-server.port=6070',
            '--init.validate-checksum=true', '--init.force=false',
            '--init.validate-genesis-assertion=true', '--init.download-path=/data/downloads']
    if state['family'] == 'arbitrum':
        # v3.12.1 latestSnapshotKind maps path + pruned to full-path.
        args += ['--init.latest=pruned', '--init.latest-base=https://snapshot.arbitrum.foundation/']
    else:
        feeds = {
            'mainnet': ('wss://feed.mainnet.chain.robinhood.com', 'https://sequencer.mainnet.chain.robinhood.com'),
            'testnet': ('wss://feed.testnet.chain.robinhood.com', 'https://sequencer.testnet.chain.robinhood.com'),
        }
        feed, sequencer = feeds[state['network']]
        args += ['--node.feed.input.url=' + feed, '--execution.forwarding-target=' + sequencer]
        if state['network'] == 'mainnet':
            args += ['--init.genesis-json-file=/config/genesis.json',
                     '--node.feed.input.secondary-url=wss://delayed-feed.mainnet.chain.robinhood.com']
    return args


def image(state):
    return 'docker.io/offchainlabs/nitro-node@' + pin(state)['image']


def verify_image(state):
    actual = json.loads(run([*DOCKER, 'image', 'inspect', image(state)]))
    require(isinstance(actual, list) and len(actual) == 1 and actual[0].get('Architecture') == state['platform']
            and actual[0].get('Os') == 'linux', 'installed Nitro image platform differs from the reviewed pin')
    require(any(value.endswith('@' + pin(state)['image']) for value in actual[0].get('RepoDigests', [])),
            'Nitro image is not the reviewed content digest')


def execute(state):
    guard(state)
    verify_image(state)
    uid, gid = state.get('service_uid'), state.get('service_gid')
    require(all(type(value) is int and 100 <= value <= 65534 for value in (uid, gid)), 'invalid Nitro service identity')
    previous = check_container(state)
    if previous is not None:
        require(previous.get('State', {}).get('Running') is False, 'Nitro container already running outside its service')
        identity = previous.get('Id')
        require(isinstance(identity, str) and re.fullmatch('[a-f0-9]{64}', identity), 'ambiguous stopped container identity')
        run([*DOCKER, 'container', 'rm', identity])
    name = unit(state)
    argv = [*DOCKER, 'run', '--pull=never', '--rm', '--name', name, '--network=host', '--read-only',
            '--label=erpc.owner=' + state['owner'], '--label=erpc.family=' + state['family'],
            '--label=erpc.network=' + state['network'],
            '--cap-drop=ALL', '--security-opt=no-new-privileges', '--user=' + str(uid) + ':' + str(gid),
            '--stop-timeout=1800', '--tmpfs=/tmp:rw,nosuid,nodev,size=4g',
            '--volume=' + str(ROOT / 'data') + ':/data:rw',
            '--volume=' + str(ROOT / 'data/cache') + ':/home/user/.cache:rw',
            '--volume=' + str(CONF) + ':/config:ro', image(state), *arguments(state)]
    os.execve(argv[0], argv, docker_environment())


def stop_container(state):
    check(state, state)
    container = check_container(state)
    if container is None:
        return
    identity = container.get('Id')
    require(isinstance(identity, str) and re.fullmatch('[a-f0-9]{64}', identity), 'ambiguous container identity')
    run([*DOCKER, 'container', 'stop', '--time=1800', identity], timeout=1860)


def install_upstreams(state, request):
    validating = request.get('action') == 'validate-upstreams'
    require(validating or state['phase'] in ('prepared', 'installing'), 'upstream changes require a prepared or fenced installation')
    if not validating:
        if state['phase'] == 'installing':
            check_deploy(state, request)
        else:
            require(state.get('generation', 0) == 0 and state.get('target') is None, 'cancelled preparation cannot install credentials')
        require(request['config_id'] == state.get('target', state)['config_id'], 'upstream installation belongs to another desired configuration')
    raw = request.get('secret')
    require(isinstance(raw, str) and 0 < len(raw.encode()) <= 65536, 'invalid concealed upstream data')
    # The shared proxy validates exact schema, destination boundaries and actual
    # Ethereum execution/beacon identity; its errors intentionally contain no URL.
    import importlib.util
    spec = importlib.util.spec_from_file_location('upstreams', '/usr/local/lib/erpc/nitro-upstreams.py')
    proxy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(proxy)
    proxy.Upstreams(proxy.strict_json(raw), network(state)[1]).verify()
    if validating:
        return {'upstreams': 'parent identity verified; no changes'}
    temporary = CONF / 'l1-upstreams.new'
    require(not temporary.is_symlink(), 'unsafe encrypted credential destination')
    temporary.unlink(missing_ok=True)
    run(['systemd-creds', 'encrypt', '--with-key=host', '--name=l1-upstreams', '-', str(temporary)], input=raw.encode())
    require(temporary.is_file() and not temporary.is_symlink(), 'encrypted credential was not created')
    temporary.chmod(0o600)
    with temporary.open('rb') as stream:
        os.fsync(stream.fileno())
    os.replace(temporary, CONF / 'l1-upstreams.cred')
    fd = os.open(CONF, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return {'upstreams': 'encrypted and parent identity verified'}


def rpc(method, params=None, port=8547):
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or []}).encode()
    request = urllib.request.Request('http://127.0.0.1:' + str(port), data=body, headers={'Content-Type': 'application/json'})
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *_args, **_kwargs):
            raise Refused('local inspection cannot redirect')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=10) as response:
        raw = response.read(1024 * 1024 + 1)
    require(len(raw) <= 1024 * 1024, 'oversized Nitro inspection response')
    value = json.loads(raw)
    require(value.get('jsonrpc') == '2.0' and value.get('id') == 1 and 'result' in value and 'error' not in value, 'RPC inspection unavailable')
    return value['result']


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


def upstream_pid(state):
    raw = run(['systemctl', 'show', '--property=MainPID', '--value', unit(state, 'upstreams')]).strip()
    require(raw.isdigit(), 'upstream service process is unavailable')
    return int(raw)


def wait_upstreams(state):
    deadline = time.monotonic() + 120
    expected = '0x1' if network(state)[1] == 'mainnet' else '0xaa36a7'
    while time.monotonic() < deadline:
        require(active(unit(state, 'upstreams')) in ('active', 'activating'), 'verified L1 transport did not start')
        if owned_ports(upstream_pid(state), (18545, 15052)):
            require(rpc('eth_chainId', port=18545) == expected, 'verified L1 transport has the wrong network')
            return
        time.sleep(1)
    raise Refused('verified L1 transport does not own its reserved loopback ports')


def latest(port):
    block = rpc('eth_getBlockByNumber', ['latest', False], port=port)
    require(isinstance(block, dict) and all(isinstance(block.get(key), str) and re.fullmatch('0x[0-9a-fA-F]{1,16}', block[key]) for key in ('timestamp', 'number')),
            'latest block inspection is missing or malformed')
    return block, int(time.time()) - int(block['timestamp'], 16)


def status(state):
    result = {'phase': state['phase'], 'network': state['network'], 'family': state['family'],
              'service': active(unit(state)), 'upstreams': active(unit(state, 'upstreams')), 'ready': False,
              'installed': state.get('installed'), 'target': state.get('target'),
              'startup_revoked': state.get('startup_revoked', False), 'generation': state.get('generation', 0),
              'controller_protocol': 2}
    try:
        firewall(state)
        result['firewall_confirmed'] = True
    except Exception:
        result['firewall_confirmed'] = False
    try:
        container = check_container(state)
        running = isinstance(container, dict) and container.get('State', {}).get('Running') is True
        result['container_running'] = running
        process = container.get('State', {}).get('Pid') if running else None
        require(running and owned_ports(process, (8547, 8548)), 'owned Nitro container has not opened its RPC listeners')
        require(owned_ports(upstream_pid(state), (18545, 15052)), 'L1 transport does not own its listeners')
        chain_id, parent, _, _ = network(state)
        require(rpc('eth_chainId') == hex(chain_id), 'Nitro network identity mismatch')
        require(rpc('eth_chainId', port=18545) == ('0x1' if parent == 'mainnet' else '0xaa36a7'), 'parent-chain identity unavailable')
        sync = rpc('eth_syncing')
        block, age = latest(8547)
        parent_block, parent_age = latest(18545)
        result.update(syncing=sync, block=block['number'], block_age_seconds=age,
                      parent_block=parent_block['number'], parent_block_age_seconds=parent_age)
        result['ready'] = (state.get('startup_revoked', False) is False and state['phase'] == 'installed' and result['service'] == 'active' and
                           result['upstreams'] == 'active' and result['firewall_confirmed'] and
                           sync is False and -120 <= age <= 600 and -120 <= parent_age <= 600)
    except Exception:
        result['inspection_error'] = 'owned Nitro/parent-chain inspection unavailable; readiness not established'
    return result


def deployment_intent(request):
    value = request.get('intent')
    require(isinstance(value, str) and re.fullmatch('[a-f0-9]{32}', value), 'invalid Nitro deployment intent')
    return value


def check_authorize(state, request):
    generation = request.get('generation')
    require(type(generation) is int and generation == state.get('generation', 0), 'Nitro lifecycle changed; observe the owner again')
    deployment_intent(request)
    target = pin(request)
    if 'target' in state:
        require(state['target'] == target, 'resume interrupted installation at its exact target')
    return target


def check_deploy(state, request):
    require(state.get('deploy_intent') == deployment_intent(request) and
            state.get('deploy_target') == pin(request), 'Nitro deployment cancelled or superseded')


def cancel(state):
    generation = state.get('generation', 0)
    require(type(generation) is int and 0 <= generation < 2**63 - 1, 'Nitro cancellation generation exhausted')
    state.update(generation=generation + 1, deploy_intent=None, deploy_target=None, startup_revoked=True)


def dispatch(state, request):
    check(state, request)
    action = request.get('action')
    if action == 'verify-helpers':
        control_destination(hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
        source = Path(__file__).with_name('upstreams.py')
        file_hash(NAMESPACE / 'nitro-upstreams.py', hashlib.sha256(source.read_bytes()).hexdigest())
        return {'helpers': 'published from the sealed source'}
    if action == 'capabilities':
        return {'controller_protocol': 2}
    if action == 'check-owner':
        control_destination()
        return {'owner': 'verified'}
    if action in ('check-authorize', 'authorize-deploy'):
        control_destination()
        target = check_authorize(state, request)
        if action == 'authorize-deploy':
            state.update(deploy_intent=deployment_intent(request), deploy_target=target)
            save(state)
        return {'authorized': True}
    if action in ('check-deploy', 'begin-install', 'pull-image', 'finish-install'):
        check_deploy(state, request)
    if action == 'check-deploy':
        return {'authorized': True}
    if action == 'status':
        return status(state)
    if action in ('install-upstreams', 'validate-upstreams'):
        return install_upstreams(state, request)
    if action == 'begin-install':
        control_destination()
        target = pin(request)
        capacity(state)
        previous = state.get('installed', pin(state))['version']
        require(tuple(map(int, target['version'].split('.'))) >= tuple(map(int, previous.split('.'))), 'Nitro database downgrades are refused')
        if state['phase'] == 'installing':
            require(state['target'] == target, 'resume interrupted installation at the same release')
        state.update(phase='installing', target=target, startup_revoked=True)
        save(state)
        stop(state)
        return {'phase': 'installing'}
    if action == 'pull-image':
        require(state['phase'] == 'installing' and state['target'] == pin(request), 'image pull belongs to another installation')
        run([*DOCKER, 'pull', image(request)], timeout=7200)
        verify_image(request)
        return {'image': 'reviewed digest installed'}
    if action == 'finish-install':
        require(state['phase'] == 'installing' and state['target'] == pin(request), 'installation target lost')
        artifacts(state)
        verify_image(request)
        uid, gid = request.get('service_uid'), request.get('service_gid')
        require(all(type(value) is int and 100 <= value <= 65534 for value in (uid, gid)), 'invalid Nitro service identity')
        candidate = dict(state, service_uid=uid, service_gid=gid, installed=state['target'],
                         version=request['version'], commit=request['commit'], config_id=request['config_id'],
                         firewall=request['firewall'], phase='installed', startup_revoked=False)
        candidate.pop('target')
        guard(candidate)
        save(candidate)
        return {'phase': 'installed'}
    if action in ('start', 'restart', 'operator-start', 'operator-restart'):
        require(pin(request) == state.get('installed'), 'inventory configuration differs; resume deployment')
        if action.startswith('operator-'):
            require('intent' not in request and type(request.get('generation')) is int and request['generation'] == state.get('generation', 0), 'explicit Nitro startup observed a stale lifecycle')
            cancel(state)
            action = action.removeprefix('operator-')
        else:
            # Old queued playbooks supplied no intent: they must never be
            # interpreted as a new operator start after a cancellation.
            check_deploy(state, request)
        candidate = dict(state, startup_revoked=False)
        guard(candidate)
        if action == 'restart':
            state['startup_revoked'] = True
            save(state)
            stop(state)
        save(candidate)
        for component in ('upstreams', 'nitro'):
            run(['systemctl', 'enable', unit(state, component)])
            run(['systemctl', 'start', unit(state, component)], timeout=240)
            require(active(unit(state, component)) == 'active', 'Nitro service did not start')
        candidate.update(deploy_intent=None, deploy_target=None)
        save(candidate)
        return status(candidate)
    if action in ('stop', 'destroy'):
        cancel(state)
        if action == 'destroy':
            state['phase'] = 'retired'
        try:
            save(state)
        except Exception:
            # Even failed fence publication must attempt owned shutdown. Never
            # claim durable cancellation when the storage write did not succeed.
            try:
                stop(state)
            finally:
                for component in ('nitro', 'upstreams'):
                    if loaded(unit(state, component)):
                        run(['systemctl', 'disable', unit(state, component)])
            raise Refused('Nitro stopped but cancellation could not be persisted; repair ownership storage') from None
        stop(state)
        for component in ('nitro', 'upstreams'):
            if loaded(unit(state, component)):
                run(['systemctl', 'disable', unit(state, component)])
        return {'phase': state['phase'], 'data_preserved': True}
    raise Refused('unsupported Nitro operation')


def locked(request, in_play=False):
    # Carried Ansible plays already own node-run.sh's operation lock. Standalone
    # mutations refuse to compete with an active play or firewall transition.
    operation = None
    if not in_play and request.get('action') not in ('status', 'validate-upstreams'):
        operation = os.open(OPERATION_ROOT, os.O_RDONLY)
        try:
            fcntl.flock(operation, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except Exception:
            os.close(operation)
            raise Refused('another node operation is active; resume after it finishes') from None
    try:
        fd = os.open(LOCK, os.O_CREAT | os.O_NOFOLLOW | os.O_RDWR, 0o600)
        with os.fdopen(fd, 'w') as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            return prepare(request) if request.get('action') == 'prepare' else dispatch(state_read(), request)
    finally:
        if operation is not None:
            os.close(operation)


def main():
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    require(os.geteuid() == 0, 'root is required')
    if sys.argv[1:] == ['stop-container']:
        stop_container(state_read())
        return
    if sys.argv[1:] == ['execute']:
        execute(state_read())
        return
    if sys.argv[1:] in (['guard'], ['guard-node']):
        state = state_read()
        guard(state)
        if sys.argv[1:] == ['guard-node']:
            wait_upstreams(state)
        return
    require(sys.argv[1:] in ([], ['play'], ['published-play']), 'unsupported controller invocation')
    if sys.argv[1:] == ['published-play']:
        control_destination(hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    raw = sys.stdin.buffer.read(262145)
    require(len(raw) <= 262144, 'request too large')
    print(json.dumps(locked(json.loads(raw), in_play=sys.argv[1:] in (['play'], ['published-play']))))


if __name__ == '__main__':
    try:
        main()
    except Refused as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
    except Exception:
        print('Nitro operation failed; inspect the owned service journal', file=sys.stderr)
        sys.exit(1)
