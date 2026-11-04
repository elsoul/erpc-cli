#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Bitcoin lifecycle controller: exact host contract before every mutation.

Core authentication stays on the host via its private cookie. There are no wallet,
transaction, arbitrary-RPC or shell-command entry points.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path('/var/lib/erpc-bitcoin')
OPT = Path('/opt/erpc-bitcoin')
CONF = Path('/etc/erpc/bitcoin.conf')
UNIT = 'erpc-bitcoin'
LOCK = Path('/run/lock/erpc-bitcoin.lock')
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


def contract(request):
    return {key: request[key] for key in ('owner', 'network', 'storage', 'prune_mib')}


def configuration(state):
    chain, rpc_port, peer_port, _ = NETWORKS[state['network']]
    return (f'chain={chain}\nserver=1\ndaemon=0\ndisablewallet=1\nrest=0\ndbcache=1024\n'
            f'prune={state["prune_mib"]}\ntxindex={int(state["storage"] == "full")}\n\n'
            f'[{chain}]\nrpcbind=127.0.0.1\nrpcallowip=127.0.0.1\nrpcport={rpc_port}\nport={peer_port}\n')


def read_state():
    path = ROOT / 'owner.json'
    require(path.is_file() and not path.is_symlink(), 'Bitcoin host ownership is missing or unsafe')
    state = json.loads(path.read_text())
    validate(state)
    require(state.get('phase') in ('prepared', 'installing', 'installed', 'retired'), 'unknown Bitcoin ownership format')
    return state


def save(state):
    path = ROOT / 'owner.json'
    temporary = ROOT / 'owner.new'
    require(not path.is_symlink() and not temporary.is_symlink(), 'unsafe ownership file')
    temporary.unlink(missing_ok=True)
    fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(state, stream)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    fd = os.open(ROOT, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def run(argv, timeout=120, allowed=(0,)):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    require(result.returncode in allowed, 'Bitcoin service operation failed; inspect the owned service journal')
    return result.stdout


def loaded(unit=UNIT):
    result = run(['systemctl', 'show', '--property=LoadState', '--value', unit], allowed=(0, 1)).strip()
    require(result in (b'not-found', b'loaded', b'masked'), 'could not determine service ownership')
    return result != b'not-found'


def active():
    result = subprocess.run(['systemctl', 'is-active', UNIT], capture_output=True, check=False)
    return result.stdout.decode().strip()


def stop():
    if loaded():
        run(['systemctl', 'stop', UNIT], timeout=660)
        require(active() in ('inactive', 'failed', 'unknown'), 'Bitcoin has not stopped cleanly')
        require(run(['systemctl', 'show', '--property=MainPID', '--value', UNIT]).strip() in (b'0', b''), 'Bitcoin process still exists')


def cli(method, *arguments):
    allowed = {'getblockchaininfo', 'getblockhash', 'getindexinfo', 'getnetworkinfo', 'getblockheader'}
    require(method in allowed, 'unsupported inspection RPC')
    result = run(['runuser', '-u', 'bitcoin', '--', str(OPT / 'current/bin/bitcoin-cli'),
                  '-conf=' + str(CONF), '-datadir=' + str(ROOT / 'data'), '-rpcclienttimeout=10', method, *arguments], timeout=15)
    require(len(result) <= 1024 * 1024, 'inspection response too large')
    # Bitcoin Core CLI prints RPC string results without JSON quotes (v31.1
    # src/bitcoin-cli.cpp ParseResult), unlike object/array responses.
    if method == 'getblockhash':
        block_hash = result.decode().strip()
        require(re.fullmatch('[a-f0-9]{64}', block_hash), 'invalid genesis hash output')
        return block_hash
    return json.loads(result)


def check(state, request):
    validate(request)
    require(contract(state) == contract(request), 'Bitcoin host ownership/network/retention mismatch; nothing changed')
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
            raw = run(['du', '-sx', '-B1', str(path)]).split()
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
    require(not ROOT.is_symlink(), 'unsafe Bitcoin root')
    if (ROOT / 'owner.json').exists():
        state = read_state()
        check(state, request)
        capacity(state)
        return {'phase': state['phase'], 'already_owned': True}
    # A failed initialization never grants authority over a pre-existing daemon/datadir.
    require(not loaded() and not loaded('bitcoind'), 'an unowned Bitcoin service exists')
    require(not (ROOT / 'data').exists(), 'unowned Bitcoin data exists; explicit manual recovery required')
    ROOT.mkdir(mode=0o755, parents=True, exist_ok=True)
    state = dict(contract(request), phase='prepared')
    capacity(state)
    save(state)
    return {'phase': 'prepared'}


def release_pin(request):
    pin = request['pin']
    version(pin['version'])
    require(re.fullmatch('[a-f0-9]{40}', pin['commit']) and re.fullmatch('[a-f0-9]{64}', pin['sha256']), 'invalid release pin')
    require(pin['platform'] in ('x86_64-linux-gnu', 'aarch64-linux-gnu'), 'unsupported release platform')
    return pin


def release_dir(pin):
    return OPT / 'releases' / (pin['version'] + '-' + pin['platform'])


def guard(state):
    check(state, state)
    capacity(state)
    require(state['phase'] == 'installed', 'Bitcoin installation is incomplete or retired')
    pin = release_pin({'pin': state['installed']})
    require((OPT / 'current').is_symlink() and (OPT / 'current').resolve() == release_dir(pin).resolve(), 'Bitcoin binary selection differs from verified release')
    marker = release_dir(pin) / 'verified.json'
    require(marker.is_file() and not marker.is_symlink() and json.loads(marker.read_text()) == pin, 'Bitcoin release verification marker missing')


def status(state):
    result = {'phase': state['phase'], 'service': active(), 'network': state['network'], 'rpc_available': False,
              'installed': state.get('installed'), 'target': state.get('target')}
    try:
        result['blockchain'] = cli('getblockchaininfo')
        result['genesis'] = cli('getblockhash', '0')
        result['indexes'] = cli('getindexinfo')
        network = cli('getnetworkinfo')
        result['connections'] = network['connections']
        result['version'] = network['version']
        block_hash = result['blockchain']['bestblockhash']
        require(re.fullmatch('[a-f0-9]{64}', block_hash), 'invalid best block hash')
        result['tip_time'] = cli('getblockheader', block_hash)['time']
        result['rpc_available'] = True
    except (Refused, KeyError, ValueError, OSError):
        result['inspection_error'] = 'RPC unavailable, warming up or malformed; readiness is not established'
    return result


def dispatch(state, request):
    check(state, request)  # Before EVERY operation, including stop and destroy.
    action = request.get('action')
    if action == 'status':
        return status(state)
    if action == 'begin-install':
        capacity(state)
        pin = release_pin(request)
        if state.get('installed'):
            require(version(pin['version']) >= version(state['installed']['version']), 'database downgrades are refused')
        if state['phase'] == 'installing':
            require(state['target'] == pin, 'resume the interrupted target before changing release')
        state.update(phase='installing', target=pin)
        save(state)  # Reboots cannot start a partly installed release.
        stop()
        return {'phase': 'installing'}
    if action == 'finish-install':
        pin = release_pin(request)
        require(state['phase'] == 'installing' and state['target'] == pin, 'release installation lost its target ownership')
        require(json.loads((release_dir(pin) / 'verified.json').read_text()) == pin, 'verified installation marker does not match')
        require((OPT / 'current').resolve() == release_dir(pin).resolve(), 'wrong release selected')
        state.update(phase='installed', installed=pin)
        state.pop('target')
        save(state)
        guard(state)
        return {'phase': 'installed'}
    if action in ('start', 'restart'):
        require(release_pin(request) == state.get('installed'), 'inventory release differs from installed release; resume deployment')
        guard(state)
        if action == 'restart':
            stop()
        run(['systemctl', 'enable', UNIT])
        run(['systemctl', 'start', UNIT])
        require(active() == 'active', 'Bitcoin service did not start')
        return status(state)
    if action == 'stop':
        require(state['phase'] != 'installing', 'resume interrupted deployment before service operations')
        stop()
        if loaded():
            run(['systemctl', 'disable', UNIT])
        return {'phase': state['phase'], 'service': 'stopped', 'data_preserved': True}
    if action == 'destroy':
        require(state['phase'] != 'installing', 'finish interrupted deployment before retiring the node')
        state['phase'] = 'retired'
        save(state)
        stop()
        if loaded():
            run(['systemctl', 'disable', UNIT])
        return {'phase': 'retired', 'service': 'stopped', 'data_preserved': True, 'ownership_preserved': True}
    raise Refused('unsupported Bitcoin lifecycle operation')


def locked(request):
    # The lock's parent is root-owned; it is separate from the owner/data directory.
    fd = os.open(LOCK, os.O_CREAT | os.O_NOFOLLOW | os.O_RDWR, 0o600)
    with os.fdopen(fd, 'w') as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        if request.get('action') == 'prepare':
            return prepare(request)
        return dispatch(read_state(), request)


def main():
    os.umask(0o077)
    require(os.geteuid() == 0, 'root is required')
    if sys.argv[1:] == ['guard']:
        guard(read_state())
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
