# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Sealed read-only Robinhood admission probe using an owned RPC host's L1 provider.

No installed Python is imported and no node configuration, account, key, service
or signing history is changed. Only the run's bounded public result is written.
"""
import hashlib
import os
from pathlib import Path
import re
import resource
import subprocess
import sys
import follower
import observation
import upstreams
from storage import decode, directory, encode, read, require, write

SOURCE = Path(__file__).absolute().parent
RUNS = Path('/opt/erpc/runs')
PROFILE = frozenset(('catalog.json', 'control.py', 'entry.py', 'observation.py', 'follower.py', 'storage.py', 'upstreams.py'))
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}


def request(value):
    require(isinstance(value, dict) and set(value) == {'schema', 'action', 'rpc_node', 'validator_address', 'intent'}
            and type(value['schema']) is int and value['schema'] == 1
            and value['action'] in ('status', 'prepare', 'validate'), 'closed public admission request required')
    node = value['rpc_node']
    require(isinstance(node, dict) and set(node) == {'owner', 'family', 'network', 'version', 'commit', 'platform', 'config_id', 'action'}
            and node['family'] == 'robinhood' and node['network'] in observation.PROFILES
            and node['action'] == 'admission-observe', 'original Robinhood RPC scope required')
    follower.validate(node); observation.address(value['validator_address'])
    require(isinstance(value['intent'], dict) if value['action'] == 'validate' else value['intent'] is None,
            'public intent is accepted only for validation')
    require(len(encode(value)) <= 16384, 'public admission request exceeds its bound')
    return node


def original(node):
    state = follower.state_read(); follower.check(state, node)
    require(state['phase'] == 'installed' and follower.pin(state) == follower.pin(node),
            'use the original settled RPC configuration before observing admission')
    directory(follower.CONF)
    return hashlib.sha256(read(follower.ROOT/'owner.json', 65536, mode=0o600)).hexdigest()


def providers():
    cipher = read(follower.CONF/'l1-upstreams.cred', 131072, mode=0o600)
    result = subprocess.run(['/usr/bin/systemd-creds', 'decrypt', '--name=l1-upstreams', '-', '-'],
        input=cipher, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, check=False,
        close_fds=True, env=ENV)
    require(result.returncode == 0 and 0 < len(result.stdout) <= 65536, 'original L1 provider custody is unavailable')
    config = upstreams.strict_json(result.stdout)
    return config, hashlib.sha256(cipher).hexdigest()


def observe(value):
    node = request(value); owner_hash = original(node)
    config, cipher_hash = providers()
    require(original(node) == owner_hash, 'original RPC scope changed before provider access')
    provider = upstreams.Upstreams(config, follower.network(node)[1])
    require(provider.execution.tls and provider.beacon.tls
            and not provider.execution.loopback and not provider.beacon.loopback,
            'admission observations require authenticated public HTTPS parent endpoints')
    # The shared proxy retains DNS/IP, TLS, redirect, header and method boundaries.
    # This process only needs small fixed-purpose parent responses.
    upstreams.MAX_RESPONSE = 1024*1024
    def rpc(method, params):
        require(method in ('eth_chainId', 'eth_getBlockByNumber', 'eth_getCode', 'eth_call'),
                'unsupported admission observation method')
        query = {'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}
        answer = provider.execution_request(encode(query))
        require(isinstance(answer, dict) and 'result' in answer and 'error' not in answer,
                'parent admission observation is unavailable')
        return answer['result']
    public = observation.observe(rpc, node['network'], value['validator_address'])
    if value['action'] == 'prepare': result = observation.prepare(public)
    elif value['action'] == 'validate': result = observation.validate(value['intent'], public, rpc)
    else: result = public
    require(original(node) == owner_hash
            and hashlib.sha256(read(follower.CONF/'l1-upstreams.cred', 131072, mode=0o600)).hexdigest() == cipher_hash,
            'original RPC provider configuration changed during observation')
    return result


def publish(source, value, result):
    run = source.parent.parent.parent
    require(source.name == 'node' and source.parent.name == 'robinhood-admission'
            and source.parent.parent.name == 'bundle' and run.parent == RUNS
            and re.fullmatch('r-[a-z0-9-]{8,40}', run.name), 'not an original sealed admission run')
    directory(source)
    require({path.name for path in source.iterdir()} == PROFILE, 'admission source profile differs')
    helpers = hashlib.sha256()
    for name in sorted(PROFILE):
        helpers.update(name.encode()+b'\0'+hashlib.sha256(read(source/name, 1024*1024)).digest())
    bundle = hashlib.sha256(read(run/'bundle.tar.gz', 64*1024*1024)).hexdigest()
    envelope = {'schema': 'erpc-robinhood-admission-public-result-v1', 'run': run.name,
        'bundle_sha256': bundle, 'helpers_sha256': helpers.hexdigest(),
        'request_sha256': hashlib.sha256(encode(value)).hexdigest(), 'result': result}
    raw = encode(envelope); require(len(raw) <= 65536, 'public admission result exceeds its bound')
    write(run/'robinhood-admission-public-result.json', raw, mode=0o644)
    return {'public_result_written': True, 'run': run.name}


def main():
    os.umask(0o077); resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.environ.clear(); os.environ.update(ENV)
    require(os.geteuid() == 0 and sys.flags.isolated and sys.argv[1:] == ['observe'],
            'isolated sealed admission invocation required')
    raw = sys.stdin.buffer.read(16385); require(0 < len(raw) <= 16384, 'invalid bounded public request')
    value = decode(raw); request(value)
    result = observe(value)
    print(encode(publish(SOURCE, value, result)).decode())


if __name__ == '__main__':
    try: main()
    except Exception:
        print('Robinhood admission observation refused; private provider diagnostics withheld', file=sys.stderr)
        raise SystemExit(1) from None
