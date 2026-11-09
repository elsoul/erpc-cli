#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Pinned public configuration and first-time peer identity preparation, never node startup."""
import hashlib
import ipaddress
import json
import lzma
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import time
import urllib.parse
import urllib.request

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

if __name__ == "__main__":
    trusted_imports(os.path.dirname(os.path.abspath(__file__)))

from control import Control, PINS, PREVIOUS_PINS, Refused, block_age


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Refused('artifact redirects are refused')


def source(network, kind, url):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != 'https' or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.port not in (None, 443):
        raise Refused('invalid public artifact URL')
    if kind == 'config':
        host = 's3-us-west-1.amazonaws.com'
        path = '/build.nearprotocol.com/nearcore-deploy/' + network + '/rpc/config.json'
    elif network == 'mainnet':
        host = 'raw.githubusercontent.com'
        path = '/near/nearcore/' + PINS[network]['commit'] + '/utils/mainnet-res/res/mainnet_genesis.json'
    else:
        host = 's3-us-west-1.amazonaws.com'
        path = '/build.nearprotocol.com/nearcore-deploy/testnet/genesis.json.xz'
    if parsed.hostname != host or parsed.path != path:
        raise Refused('artifact origin/path differs from the reviewed network pin')


def fetch(network, kind, url, destination, expected):
    source(network, kind, url)
    limit = 1024 * 1024 if kind == 'config' else 256 * 1024 * 1024
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    digest, total, started = hashlib.sha256(), 0, time.monotonic()
    with opener.open(urllib.request.Request(url, headers={'Accept-Encoding': 'identity'}), timeout=30) as response:
        if response.status != 200 or response.headers.get('Content-Encoding', 'identity') != 'identity':
            raise Refused('artifact response is not a raw successful payload')
        with destination.open('wb') as output:
            while block := response.read(1024 * 1024):
                total += len(block)
                if total > limit or time.monotonic() - started > 1800:
                    raise Refused('artifact exceeds its bounded download budget')
                digest.update(block)
                output.write(block)
    if digest.hexdigest() != expected:
        raise Refused('artifact digest differs from the reviewed pin')


def configuration(original, expected, public_rpc, public_metrics, peers):
    if not isinstance(original, dict) or not isinstance(original.get('rpc'), dict) or not isinstance(original.get('network'), dict):
        raise Refused('invalid official base configuration')
    config = json.loads(json.dumps(original))
    config.update({'genesis_file': '/etc/near/genesis.json', 'genesis_records_file': None,
                   'node_key_file': '/run/near-keys/node_key.json',
                   'validator_key_file': '/etc/near/disabled-validator.json',
                   'tracked_shards_config': 'AllShards', 'archive': False,
                   'save_trie_changes': True, 'gc_num_epochs_to_keep': 5,
                   'telemetry': {'endpoints': []}})
    for field in ('tracked_shards', 'tracked_accounts', 'tracked_shadow_validator', 'tracked_shard_schedule',
                  'cloud_archival', 'cloud_archival_writer', 'cold_store', 'rosetta_rpc', 'tx_generator', 'rpc_probe', 'gc'):
        config.pop(field, None)
    config['network']['addr'] = '0.0.0.0:24567'
    if not isinstance(peers, list) or not 1 <= len(peers) <= 64:
        raise Refused('initial synchronization requires qualified bootstrap peers')
    checked = []
    for value in peers:
        public, endpoint = value.split('@')
        checked.append(peer_key(public) + '@' + peer_endpoint(endpoint))
    config['network']['boot_nodes'] = ','.join(checked)
    config['rpc'].update({'addr': ('0.0.0.0' if public_rpc else '127.0.0.1') + ':3030',
                          'prometheus_addr': ('0.0.0.0' if public_metrics else '127.0.0.1') + ':3032',
                          'cors_allowed_origins': [], 'enable_debug_rpc': False,
                          'experimental_debug_pages_src_path': None, 'sharded_rpc': None})
    if expected['role'] == 'validator':
        if public_rpc: raise Refused('dedicated validators keep RPC on loopback')
        config['validator_key_file'] = '/run/near-keys/validator_key.json'
    config.setdefault('store', {})['path'] = '/var/lib/near/data'
    return config


def peer_key(value):
    if not isinstance(value, str) or not re.fullmatch('ed25519:[1-9A-HJ-NP-Za-km-z]{32,44}', value):
        raise Refused('unsupported public peer identity')
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    encoded = value[8:]
    number = 0
    for char in encoded: number = number * 58 + alphabet.index(char)
    decoded = b'\0' * (len(encoded) - len(encoded.lstrip('1'))) + number.to_bytes((number.bit_length() + 7) // 8, 'big')
    if len(decoded) != 32 or not any(decoded): raise Refused('invalid peer public-key length')
    return value


def peer_endpoint(value):
    if not isinstance(value, str) or len(value) > 80 or '%' in value:
        raise Refused('invalid peer socket address')
    parsed = urllib.parse.urlsplit('//' + value)
    if parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
        raise Refused('peer address must be a numeric socket')
    address = ipaddress.ip_address(parsed.hostname)
    port = parsed.port
    if port is None or not 1 <= port <= 65535:
        raise Refused('peer address requires an explicit valid port')
    if address.version == 4:
        excluded = (
            '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
            '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24',
            '192.31.196.0/24', '192.52.193.0/24', '192.88.99.0/24', '192.168.0.0/16',
            '192.175.48.0/24', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24',
            '224.0.0.0/4', '240.0.0.0/4')
    else:
        # Ordinary global unicast only: mapped/compatible IPv4, site/link-local,
        # NAT64, dummy, multicast and other reserved space cannot enter through
        # version-dependent stdlib is_global classifications.
        if address not in ipaddress.IPv6Network('2000::/3'):
            raise Refused('peer address must be ordinary global IPv6 unicast')
        excluded = ('2001::/23', '2001:db8::/32', '2002::/16', '2620:4f:8000::/48', '3ffe::/16', '3fff::/20')
    # Conservative IANA special-use policy (2026-10-26), including service anycast.
    if any(address in ipaddress.ip_network(prefix) for prefix in excluded):
        raise Refused('special-purpose protocol addresses are not bootstrap peers')
    host = '[' + str(address) + ']' if address.version == 6 else str(address)
    return host + ':' + str(port)


def peer_list(value):
    active, producers = value.get('active_peers'), value.get('known_producers')
    if not isinstance(active, list) or not isinstance(producers, list) or len(active) > 1000 or len(producers) > 5000:
        raise Refused('public bootstrap peer response is missing or oversized')
    known = {entry.get('peer_id') for entry in producers if isinstance(entry, dict) and isinstance(entry.get('peer_id'), str)}
    result = set()
    for entry in active:
        if not isinstance(entry, dict) or not isinstance(entry.get('id'), str) or entry['id'] not in known:
            continue
        try:
            result.add(peer_key(entry['id']) + '@' + peer_endpoint(entry.get('addr')))
        except (Refused, ValueError, TypeError):
            continue  # Unreachable/unsupported peers never become outbound targets.
    if not result: raise Refused('official bootstrap observation contains no qualified reachable producer peers')
    return sorted(result)[:64]


def observe_bootstrap(expected, url):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != 'https' or parsed.netloc != 'rpc.' + expected['network'] + '.near.org' or parsed.path not in ('', '/') or parsed.query or parsed.fragment:
        raise Refused('bootstrap observer must be the fixed official network RPC')
    base = url.rstrip('/')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    def query(path, body=None):
        request = urllib.request.Request(base + path, data=None if body is None else json.dumps(body).encode(),
                                         headers={'Content-Type': 'application/json', 'Accept-Encoding': 'identity'})
        with opener.open(request, timeout=20) as response:
            if response.status != 200 or response.headers.get('Content-Encoding', 'identity') != 'identity':
                raise Refused('public bootstrap response is not successful identity-encoded JSON')
            raw = response.read(2 * 1024 * 1024 + 1)
        if len(raw) > 2 * 1024 * 1024: raise Refused('public bootstrap response exceeds its bound')
        return json.loads(raw)
    status = query('/status')
    if status.get('chain_id') != expected['network'] or status.get('genesis_hash') != expected['genesis_hash']:
        raise Refused('bootstrap observer has the wrong network genesis')
    age = block_age(status['sync_info']['latest_block_time'])
    if status['sync_info']['syncing'] is not False or not -120 <= age <= 300:
        raise Refused('bootstrap observer is syncing or stale')
    response = query('/', {'jsonrpc': '2.0', 'id': 'erpc-bootstrap', 'method': 'network_info', 'params': []})
    if response.get('jsonrpc') != '2.0' or response.get('id') != 'erpc-bootstrap' or 'error' in response or not isinstance(response.get('result'), dict):
        raise Refused('network_info observation did not return a matching response')
    return peer_list(response['result'])


def bootstrap(control, expected, request):
    key = {'contract': expected, 'image': PINS[expected['network']]['image'], 'policy': request['policy_sha256']}
    if (control.directory / 'installing.json').exists():
        saved = control.read('bootstrap.json')
        if saved.get('request') != key:
            pending=control.target(expected,control.read('installing.json'),qualified=False)
            journal=control.state_path(control.upgrade_name(expected))
            if journal.exists():
                history=control.upgrade_record(expected)
                if (saved!=history['bootstrap'] or pending not in (history['from'],history['to'])
                        or history['to']['policy_sha256']!=request['policy_sha256']):
                    raise Refused('resume the original exact forward-update bootstrap')
                original=history['from']
            else:
                original=pending
                pin=PREVIOUS_PINS.get(expected['network'])
                if (request.get('allow_pending_upgrade') is not True or pin is None
                        or any(original[field]!=pin[field] for field in pin)):
                    raise Refused('use explicit update for the qualified older pending release')
            previous_key=dict(key,image=original['image'])
            if saved.get('request')!=previous_key or original['policy_sha256']!=request['policy_sha256']:
                raise Refused('pending update must retain the original bootstrap and access policy')
        if not isinstance(saved.get('peers'), list) or not 1 <= len(saved['peers']) <= 64:
            raise Refused('incomplete installation requires its original bootstrap observation')
        peers = []
        for value in saved['peers']:
            public, endpoint = value.split('@')
            peers.append(peer_key(public) + '@' + peer_endpoint(endpoint))
        return peers
    peers = observe_bootstrap(expected, request['bootstrap_url'])
    control.write('bootstrap.json', {'request': key, 'peers': peers})
    return peers


def cpu_features(text):
    processors = [set(line.split(':', 1)[1].split()) for line in text.splitlines() if line.startswith('flags') and ':' in line]
    required = {'cx16', 'popcnt', 'sse4_1', 'sse4_2', 'avx', 'sha_ni'}
    if not processors or any(not required.issubset(flags) for flags in processors):
        raise Refused('CPU lacks the documented NEAR instruction-set requirements')


def peer_identity(control, expected, config, genesis, image):
    uid, gid = control.account(expected)
    encrypted = control.path('/etc/credstore.encrypted/near-node.key')
    receipt = control.directory / 'identity.json'
    pending = encrypted.with_suffix('.pending')
    if receipt.exists() and not encrypted.exists() and pending.is_file() and not pending.is_symlink():
        recorded = control.read('identity.json')
        if recorded['contract'] != expected or recorded['cipher_sha256'] != control.file_digest(pending):
            raise Refused('interrupted publication does not match the original identity receipt')
        os.replace(pending, encrypted)
    if receipt.exists() or encrypted.exists():
        # Lost material never becomes a new identity implicitly.
        control.identity(expected)
        return
    if pending.exists() or pending.is_symlink():
        raise Refused('unreceipted encrypted peer material requires explicit recovery')
    with tempfile.TemporaryDirectory(prefix='near-identity-', dir='/run') as temporary:
        home = Path(temporary)
        os.chown(home, uid, gid)
        init_config = dict(config, node_key_file='/var/lib/near/node_key.json', validator_key_file='/etc/near/disabled-validator.json')
        config_file = home / 'config.json'
        config_file.write_text(json.dumps(init_config))
        os.chmod(config_file, 0o644)
        # Existing config + genesis makes neard init generate only a peer key;
        # there is no account-id argument and no network access or validator key.
        control.docker('run', '--rm', '--network', 'none', '--read-only',
            '--user', str(uid) + ':' + str(gid), '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges=true', '--ulimit', 'core=0:0',
            '--mount', 'type=bind,src=' + str(home) + ',dst=/var/lib/near',
            '--mount', 'type=bind,src=' + str(config_file) + ',dst=/var/lib/near/config.json,readonly',
            '--mount', 'type=bind,src=' + str(genesis) + ',dst=/etc/near/genesis.json,readonly',
            '--entrypoint', '/usr/local/bin/neard', image,
            '--home', '/var/lib/near', 'init', '--chain-id', expected['network'])
        key_file = home / 'node_key.json'
        if key_file.is_symlink() or not key_file.is_file() or key_file.stat().st_size > 4096:
            raise Refused('native initializer did not produce one bounded peer key')
        key = json.loads(key_file.read_bytes())
        if set(key) != {'account_id', 'public_key', 'secret_key'} or key['account_id'] != 'node':
            raise Refused('native initializer returned an unexpected key role')
        if not all(isinstance(key[k], str) and key[k].startswith('ed25519:') for k in ('public_key', 'secret_key')):
            raise Refused('native initializer returned an unexpected key scheme')
        raw = json.dumps(key, sort_keys=True, separators=(',', ':')).encode()
        control.directory_guard(encrypted.parent, create=True, mode=0o700)
        if pending.exists():
            raise Refused('interrupted peer credential publication needs explicit recovery')
        control.command('systemd-creds', 'encrypt', '--with-key=host', '--name=node-key.json', '-', str(pending), data=raw)
        os.chmod(pending, 0o600)
        value = {'contract': expected, 'public_key': key['public_key'],
                 'plaintext_sha256': control.digest(raw), 'cipher_sha256': control.digest(pending.read_bytes())}
        # Receipt is authoritative before the credential can be selected by a service.
        control.write('identity.json', value)
        os.replace(pending, encrypted)


def prepare(control, expected, request):
    control.contract(expected)
    control.account(expected)
    cpu_features(control.path('/proc/cpuinfo').read_text())
    pin = PINS[expected['network']]
    if set(request) != {'genesis_url', 'config_url', 'bootstrap_url', 'rpc_public', 'metrics_public', 'policy_sha256', 'intent','allow_pending_upgrade'} or any(type(request[k]) is not bool for k in ('rpc_public', 'metrics_public','allow_pending_upgrade')):
        raise Refused('invalid public configuration request')
    control.capacity(expected)
    control.docker('pull', '--platform', 'linux/amd64', pin['image'])
    version = control.docker('run', '--rm', '--network', 'none', '--read-only', '--user', '65534:65534',
        '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges=true', '--ulimit', 'core=0:0',
        '--entrypoint', '/usr/local/bin/neard', pin['image'], '--version').stdout.decode()
    if not version.startswith('neard ') or '(release ' + pin['version'] + ')' not in version or '(commit ' + pin['commit'] + ')' not in version:
        raise Refused('image binary version/commit differs from the reviewed source')
    directory = control.path('/etc/near')
    control.directory_guard(directory, create=True, mode=0o755)
    with tempfile.TemporaryDirectory(prefix='.prepare-', dir=directory) as temporary:
        stage = Path(temporary)
        original = stage / 'base.json'
        genesis_archive = stage / 'genesis.download'
        cached_config = directory / 'source-config.json'
        if cached_config.is_file() and control.file_digest(cached_config) == pin['config_sha256']:
            shutil.copyfile(cached_config, original)
        else:
            fetch(expected['network'], 'config', request['config_url'], original, pin['config_sha256'])
        genesis = stage / 'genesis.json'
        cached_genesis = False
        if (control.directory / 'installed.json').exists() and (control.directory / 'genesis-source.json').exists():
            previous = control.target(expected, control.read('installed.json'), qualified=False)
            origin = control.read('genesis-source.json')
            existing = directory / 'genesis.json'
            if origin == {'network': expected['network'], 'source_sha256': pin['genesis_sha256']} and control.file_digest(existing) == previous['genesis_sha256']:
                shutil.copyfile(existing, genesis)
                cached_genesis = True
        if not cached_genesis:
            fetch(expected['network'], 'genesis', request['genesis_url'], genesis_archive, pin['genesis_sha256'])
        if not cached_genesis and expected['network'] == 'testnet':
            total = 0
            with lzma.open(genesis_archive, 'rb') as input_file, genesis.open('wb') as output:
                while block := input_file.read(1024 * 1024):
                    total += len(block)
                    if total > 16 * 1024 ** 3: raise Refused('genesis expands beyond the reviewed bound')
                    output.write(block)
        elif not cached_genesis:
            os.replace(genesis_archive, genesis)
        config = configuration(json.loads(original.read_bytes()), expected,
                               request['rpc_public'], request['metrics_public'], bootstrap(control, expected, request))
        payload = json.dumps(config, sort_keys=True, separators=(',', ':')).encode()
        target = {key: pin[key] for key in ('version', 'commit', 'image')}
        target['config_sha256'] = control.digest(payload)
        target['genesis_sha256'] = control.file_digest(genesis)
        target['policy_sha256'] = request['policy_sha256']
        control.begin_install(expected, target, request['intent'], request['allow_pending_upgrade'])
        # Only after verified download/image preflight do we stop and replace config.
        os.chmod(genesis, 0o644)
        os.replace(genesis, directory / 'genesis.json')
        os.chmod(original, 0o644)
        os.replace(original, cached_config)
        control.write('genesis-source.json', {'network': expected['network'], 'source_sha256': pin['genesis_sha256']})
        peer_identity(control, expected, config, directory / 'genesis.json', pin['image'])
        pending = stage / 'config.json'
        pending.write_bytes(payload)
        os.chmod(pending, 0o644)
        os.replace(pending, directory / 'config.json')
        control.finish_install(expected, target, request['intent'])
        return target


def main():
    import base64
    import resource
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if len(sys.argv) != 2: raise Refused('expected public ownership contract')
    expected = json.loads(base64.b64decode(sys.argv[1], validate=True))
    payload = sys.stdin.buffer.read(65537)
    if len(payload) > 65536: raise Refused('oversized setup request')
    # The carried Ansible preparation play holds the common run lock throughout.
    print(json.dumps(prepare(Control(), expected, json.loads(payload))))


if __name__ == '__main__':
    try: main()
    except Refused as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
    except Exception:
        # Download/native tool diagnostics must never turn into a secret-bearing error.
        print('NEAR preparation failed; verified artifact or identity requirements were not met', file=sys.stderr)
        raise SystemExit(1)
