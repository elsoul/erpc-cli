# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Private parent transport custody, separate from the original signing wallet."""
import scope
import hashlib
import subprocess
import host
import bounded
import upstreams
from storage import decode, directory, encode, read, require, sync_directory, synchronize, write

NAME = scope.CREDENTIAL_PREFIX+'-upstreams'


def transform(action, raw):
    require(action in ('encrypt', 'decrypt') and isinstance(raw, bytes) and len(raw) <= 131072,
            'invalid parent transport credential operation')
    argv = ['/usr/bin/systemd-creds', action, '--name='+NAME]
    if action == 'encrypt': argv.append('--with-key=host')
    result = subprocess.run([*argv, '-', '-'], input=raw, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=30, check=False, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
    require(result.returncode == 0 and 0 < len(result.stdout) <= 131072, 'parent credential operation failed')
    return result.stdout


def client(config):
    result=bounded.readonly(config)
    require(all(endpoint.tls and not endpoint.loopback for endpoint in (result.execution,result.beacon)),
            'funded validator parent providers require authenticated public HTTPS')
    return result


def sealed(state, expected):
    state.owner(expected)
    saved = state.get('upstreams.json')
    require(set(saved) == {'contract', 'cipher_sha256', 'plaintext_sha256'} and saved['contract'] == expected,
            'parent transport belongs to another owner')
    cipher = read(host.UPSTREAM_CUSTODY/'upstreams.cred', 131072, mode=0o600)
    require(hashlib.sha256(cipher).hexdigest() == saved['cipher_sha256'], 'parent credential ciphertext changed')
    return saved, cipher


def inspect(state, expected, convert=transform):
    saved, cipher = sealed(state, expected)
    raw = convert('decrypt', cipher)
    require(hashlib.sha256(raw).hexdigest() == saved['plaintext_sha256'], 'parent credential readback changed')
    config = upstreams.strict_json(raw)
    result = client(config); result.verify()
    return config


def install(state, expected, intent, raw, quiet, convert=transform):
    guard=lambda:(state.pending(expected,intent),host.namespaces(),quiet())
    return install_authorized(state,expected,intent,raw,guard,convert)


def install_authorized(state,expected,intent,raw,guard,convert=transform,validate=None):
    guard()
    require(isinstance(raw, bytes) and 0 < len(raw) <= 65536, 'parent credential exceeds its bound')
    config = upstreams.strict_json(raw); client(config).verify()
    if validate is not None:validate(config)
    canonical = encode(config); digest = hashlib.sha256(canonical).hexdigest()
    directory(host.UPSTREAM_CUSTODY, create=True, mode=0o700)
    stage = host.UPSTREAM_CUSTODY/('import-'+intent)
    directory(stage, create=True, mode=0o700)
    require({p.name for p in stage.iterdir()} <= {'upstreams.cred', 'receipt.json'}, 'unknown parent credential staging content')
    path = stage/'upstreams.cred'
    if path.exists(): cipher = read(path, 131072, mode=0o600)
    else:
        cipher = convert('encrypt', canonical); write(path, cipher)
    require(convert('decrypt', cipher) == canonical, 'parent credential intent already identifies another secret')
    saved = {'contract': expected, 'cipher_sha256': hashlib.sha256(cipher).hexdigest(), 'plaintext_sha256': digest}
    receipt = stage/'receipt.json'
    if receipt.exists(): require(decode(read(receipt, mode=0o600)) == saved, 'parent credential receipt differs')
    else: write(receipt, encode(saved))
    synchronize(path); synchronize(receipt); sync_directory(stage); guard()
    write(host.UPSTREAM_CUSTODY/'upstreams.cred', cipher); state.put('upstreams.json', saved)
    inspect(state, expected, convert)
    return {'upstreams_verified': True}
