#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Root-owned validator lifecycle helper. Requests, including custody, arrive on stdin.

Never prints subprocess diagnostics for key-management operations. The root-owned
manifest, not mutable 1Password metadata, controls signing and persistent fencing.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = Path('/var/lib/erpc-eth-validator')
CONFIG = Path('/etc/erpc/eth-validator.json')
OPT = Path('/opt/erpc-eth-validator')
UNITS = ['erpc-eth-validator', 'erpc-eth-beacon', 'erpc-eth-execution']
NETWORKS = {
    'mainnet': (1, '0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95'),
    'hoodi': (560048, '0x212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f'),
}
MAX_REQUEST = 16 * 1024 * 1024


class Refused(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Refused(message)


def read_json(path):
    require(path.is_file() and not path.is_symlink(), 'required state file missing or symlinked')
    return json.loads(path.read_text())


def atomic(path, content, mode=0o600):
    require(not path.is_symlink(), 'refusing symlink state path')
    temp = path.with_name(path.name + '.new')
    require(not temp.is_symlink(), 'refusing symlink temporary state path')
    temp.unlink(missing_ok=True)  # recover an interrupted write under the controller lock
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
        d = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(d)
        finally:
            os.close(d)
    finally:
        temp.unlink(missing_ok=True)


def save(state):
    atomic(ROOT / 'owner.json', json.dumps(state))


def run(argv, timeout=120, allowed=(0,)):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout, check=False)
    require(result.returncode in allowed, 'operation failed; signer remains stopped; inspect service state')
    return result.stdout


def ctl(action, unit):
    run(['systemctl', action, unit])


def stopped():
    state = subprocess.run(['systemctl', 'is-active', UNITS[0]], capture_output=True, check=False)
    require(state.returncode != 0 and state.stdout.strip() in (b'inactive', b'failed', b'unknown'),
            'validator is still running or stopping')
    pid = run(['systemctl', 'show', '-p', 'MainPID', '--value', UNITS[0]]).strip()
    require(pid in (b'0', b''), 'validator process has not exited')


def rpc(path, payload=None):
    url = ('http://127.0.0.1:5052' + path) if path else 'http://127.0.0.1:8545'
    data = None if payload is None else json.dumps(payload).encode()
    request = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.load(response)


def eth(method, params):
    result = rpc('', {'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params})
    require('error' not in result and 'result' in result, 'execution RPC rejected the health check')
    return result['result']


def ready(config):
    expected_id, expected_root = NETWORKS[config['network']]
    require(int(eth('eth_chainId', []), 16) == expected_id, 'execution network mismatch')
    genesis = rpc('/eth/v1/beacon/genesis')['data']
    require(genesis['genesis_validators_root'] == expected_root, 'consensus genesis mismatch')
    sync = rpc('/eth/v1/node/syncing')['data']
    expected_slot = int((time.time() - int(genesis['genesis_time'])) // 12)
    require(abs(expected_slot - int(sync['head_slot'])) <= 3, 'beacon head is stale or clock is wrong')
    require(sync.get('is_syncing') is False and sync.get('is_optimistic') is False
            and sync.get('el_offline') is False and int(sync['sync_distance']) == 0,
            'beacon or execution is not ready for signing')
    head = eth('eth_getBlockByNumber', ['latest', False])
    require(isinstance(head, dict) and abs(time.time() - int(head['timestamp'], 16)) < 120,
            'execution head is stale or clock is wrong')
    return sync


def chain_validator(pubkey):
    try:
        return rpc('/eth/v1/beacon/states/head/validators/' + pubkey)['data']
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise


def validate_material(material, config, fresh):
    key = material['keystore']
    require(key.get('version') == 4 and isinstance(key.get('crypto'), dict), 'invalid encrypted keystore')
    raw = key.get('pubkey', '')
    require(isinstance(raw, str) and re.fullmatch('[0-9a-fA-F]{96}', raw), 'invalid validator public key')
    pubkey = '0x' + raw.lower()
    require(isinstance(material['password'], str) and 0 < len(material['password']) < 4096
            and '\n' not in material['password'] and '\r' not in material['password'], 'invalid password file contents')
    history = material['history']
    require(history['metadata']['interchange_format_version'] == '5'
            and history['metadata']['genesis_validators_root'] == NETWORKS[config['network']][1],
            'slashing history network mismatch')
    entries = history['data']
    require(len(entries) == 1 and entries[0]['pubkey'] == pubkey, 'history must contain exactly the imported key')
    for name in ['signed_blocks', 'signed_attestations']:
        require(isinstance(entries[0][name], list), 'missing signing records')
        if fresh:
            require(not entries[0][name], 'used keys require managed migration')
    return pubkey


def lighthouse(config, args):
    return run(['runuser', '-u', 'ev-validator', '--', str(OPT / 'current/lighthouse'),
                '--network', config['network'], '--datadir', str(ROOT / 'vc'),
                '--logfile-max-number', '0', 'account', 'validator'] + args)


def check_state(config, state):
    require(state['owner'] == config['owner'] and state['network'] == config['network'], 'owner or network mismatch')


def custody_guard(config, state):
    check_state(config, state)
    require(state['state'] == 'imported' and not state.get('fenced_to'), 'signing is not authorized on this host')
    require(not (ROOT / 'vc/validators').is_symlink(), 'refusing symlink validators directory')
    require((ROOT / 'vc/validators/slashing_protection.sqlite').is_file() and not (ROOT / 'vc/validators/slashing_protection.sqlite').is_symlink(), 'slashing database missing or symlinked; never recreate it')
    require((ROOT / 'vc/validators/validator_definitions.yml').is_file(), 'validator definitions missing')


def guard(config, state):
    custody_guard(config, state)
    ready(config)


def wait_guard(config, state):
    custody_guard(config, state)
    for attempt in range(120):
        try:
            ready(config)
            return
        except (Refused, KeyError, ValueError, OSError):
            if attempt == 119:
                raise Refused('clients did not become signing-ready within ten minutes') from None
            time.sleep(5)


def status(config, state):
    services = {}
    for unit in UNITS:
        services[unit] = subprocess.run(['systemctl', 'is-active', unit], capture_output=True, check=False).stdout.decode().strip()
    result = {'state': state['state'], 'pubkey': state.get('pubkey', ''), 'network': config['network'],
              'services': services, 'ready': False, 'activation': 'unknown'}
    result['signer_active'] = services[UNITS[0]] == 'active'
    result['slashing_history_present'] = (ROOT / 'vc/validators/slashing_protection.sqlite').is_file()
    try:
        result['sync'] = ready(config)
        result['ready'] = True
        if state.get('pubkey'):
            found = chain_validator(state['pubkey'])
            result['activation'] = found['status'] if found else 'not_in_beacon_state'
            if found:
                result['balance_gwei'] = found['balance']
                result['slashed'] = found['validator']['slashed']
    except (Refused, KeyError, ValueError, OSError):
        result['readiness_error'] = 'network, sync, freshness or RPC check failed'
    return result


def import_keys(config, state, request):
    require(state['state'] in ('prepared', 'importing', 'imported'), 'host already owns a key or is fenced')
    material = request['material']
    migration = request.get('source_owner')
    pubkey = validate_material(material, config, not migration)
    digest = hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest()
    if state['state'] == 'imported':
        require(state.get('material_digest') == digest, 'host already owns a different import')
        require((ROOT / 'vc/validators/slashing_protection.sqlite').is_file(), 'slashing database missing; never recreate it')
        return {'state': 'imported', 'pubkey': pubkey, 'signing_started': False}
    stopped()
    if migration:
        require(material.get('destination') == config['owner'] and material.get('source') == migration,
                'migration destination or source mismatch')
    else:
        require(request.get('new_key') is True, 'new key assertion is required')
        ready(config)
        require(chain_validator(pubkey) is None, 'key already exists on chain; use managed migration')
    if state['state'] == 'importing':
        require(state['material_digest'] == digest, 'interrupted import must retry identical material')
    else:
        require(not (ROOT / 'vc/validators/slashing_protection.sqlite').exists(), 'unowned slashing database exists')
        state.update(state='importing', pubkey=pubkey, material_digest=digest)
        save(state)
    # Persist the retry input before calling Lighthouse; no secrets enter an Ansible log/bundle.
    custody = ROOT / 'custody.json'
    atomic(custody, json.dumps(material))
    stage = ROOT / 'vc/import'
    require(not stage.is_symlink(), 'refusing symlink import directory')
    stage.mkdir(mode=0o700, exist_ok=True)
    os.chmod(stage, 0o700)
    uid = pwd.getpwnam('ev-validator').pw_uid
    os.chown(stage, uid, -1)
    validators = ROOT / 'vc/validators'
    require(not validators.is_symlink(), 'refusing symlink validators directory')
    validators.mkdir(mode=0o700, exist_ok=True)
    os.chmod(validators, 0o700)
    os.chown(validators, uid, -1)
    for name, contents in [('keystore.json', json.dumps(material['keystore'])),
                           ('password', material['password']), ('history.json', json.dumps(material['history']))]:
        path = stage / name
        atomic(path, contents)
        os.chown(path, uid, -1)
    # Import history first, then encrypted key. Resume never removes the existing database.
    lighthouse(config, ['slashing-protection', 'import', str(stage / 'history.json')])
    lighthouse(config, ['import', '--keystore', str(stage / 'keystore.json'), '--reuse-password', '--password-file', str(stage / 'password')])
    require((ROOT / 'vc/validators/slashing_protection.sqlite').is_file(), 'Lighthouse did not preserve slashing protection')
    for path in stage.iterdir():
        path.unlink()
    state.update(state='imported')
    save(state)
    return {'state': 'imported', 'pubkey': pubkey, 'signing_started': False}


def fence(config, state, destination):
    require(isinstance(destination, str) and re.fullmatch('[A-Za-z0-9._-]{1,80}', destination), 'invalid migration owner')
    require(destination != config['owner'], 'cannot migrate to the same owner')
    require(state['state'] in ('imported', 'fenced'), 'no completed key import to export')
    require(state.get('fenced_to', destination) == destination, 'host already fenced to another destination')
    # Fence is durable BEFORE attempting shutdown: reboot/manual service start fails guard.
    state.update(state='fenced', fenced_to=destination)
    save(state)
    ctl('stop', UNITS[0])
    ctl('disable', UNITS[0])
    stopped()
    require((ROOT / 'vc/validators/slashing_protection.sqlite').is_file(), 'slashing database is missing')
    export = ROOT / 'vc/migration-history.json'
    export.unlink(missing_ok=True)
    lighthouse(config, ['slashing-protection', 'export', str(export)])
    material = read_json(ROOT / 'custody.json')
    material.update(history=read_json(export), source=config['owner'], destination=destination)
    validate_material(material, config, False)
    export.unlink()
    return material


def dispatch(config, state, request):
    check_state(config, state)
    require(request.get('owner') == config['owner'], 'wrong inventory owner')
    action = request.get('action')
    if action == 'install-check':
        require(state['state'] not in ('fenced', 'importing'), 'fenced or incomplete custody cannot be reconfigured')
        digest = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()
        if state['state'] == 'maintenance':
            require(state.get('config_digest') == digest, 'resume the interrupted configuration before changing it')
        else:
            state.update(prior_state=state['state'], state='maintenance', config_digest=digest)
            save(state)
        loaded = run(['systemctl', 'show', '--property=LoadState', '--value', UNITS[0]], allowed=(0, 1)).strip()
        require(loaded in (b'not-found', b'loaded', b'masked'), 'could not determine validator service state')
        if loaded != b'not-found':
            ctl('stop', UNITS[0])
            ctl('disable', UNITS[0])
            stopped()
        return {'state': 'maintenance'}
    if action == 'install-end':
        require(state['state'] == 'maintenance', 'configuration lost its maintenance ownership')
        require(state['config_digest'] == hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest(), 'configuration changed concurrently')
        state['state'] = state.pop('prior_state')
        state.pop('config_digest')
        save(state)
        return {'state': state['state'], 'signing_started': False}
    if action == 'status':
        return status(config, state)
    if action == 'import':
        return import_keys(config, state, request)
    if action == 'fence-export':
        return fence(config, state, request['destination'])
    if action == 'stop':
        ctl('stop', UNITS[0])
        ctl('disable', UNITS[0])
        stopped()
        for unit in UNITS[1:]:
            ctl('stop', unit)
            ctl('disable', unit)
        return {'state': 'stopped', 'history_preserved': True}
    if action in ('start', 'restart'):
        if action == 'restart':
            ctl('stop', UNITS[0])
            stopped()
            for unit in UNITS[1:]:
                ctl('stop', unit)
        custody_guard(config, state)
        for unit in reversed(UNITS[1:]):
            ctl('enable', unit)
            ctl('start', unit)
        wait_guard(config, state)
        ctl('enable', UNITS[0])
        ctl('start', UNITS[0])
        return status(config, state)
    if action == 'destroy':
        # This command never deletes keys, history, binaries or inventory. It may be resumed safely.
        state['state'] = 'fenced'
        save(state)
        for unit in UNITS:
            ctl('stop', unit)
            ctl('disable', unit)
        stopped()
        return {'state': 'fenced', 'keys_and_history_preserved': True}
    raise Refused('unsupported operation')


def main():
    os.umask(0o077)
    require(os.geteuid() == 0, 'root is required')
    config = read_json(CONFIG)
    require(config.get('network') in NETWORKS, 'unsupported validator network')
    # ExecStartPre runs while the controlling command owns the global lock.
    if sys.argv[1:] == ['guard']:
        wait_guard(config, read_json(ROOT / 'owner.json'))
        return
    if sys.argv[1:] in (['install-check'], ['install-end']):
        request = {'action': sys.argv[1], 'owner': config['owner']}
    else:
        raw = sys.stdin.buffer.read(MAX_REQUEST + 1)
        require(len(raw) <= MAX_REQUEST, 'request too large')
        request = json.loads(raw)
    print(json.dumps(locked_dispatch(config, request)))


def locked_dispatch(config, request):
    lock = os.open(ROOT / 'control.lock', os.O_CREAT | os.O_NOFOLLOW | os.O_RDWR, 0o600)
    with os.fdopen(lock, 'w') as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        return dispatch(config, read_json(ROOT / 'owner.json'), request)


if __name__ == '__main__':
    try:
        main()
    except Refused as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
    except Exception:
        # Input or subprocess errors can contain passwords. Never print repr/traceback.
        print('validator operation failed; no secret diagnostics were emitted', file=sys.stderr)
        sys.exit(1)
