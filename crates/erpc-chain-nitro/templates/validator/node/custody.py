# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original 1Password-backed wallet import and host-encrypted custody.

Only the controller's original concealed key enters stdin. No key generation,
transaction signing, export to logs, owner-key import or financial action exists
in this helper. Explicit restore is bound to the same immutable original key.
"""
import scope
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import crypto
import accounts
import host
from storage import decode, directory, encode, read, require, sync_directory, synchronize, write

NAME = scope.CREDENTIAL_PREFIX+'-wallet'


def canonical(raw):
    require(isinstance(raw, bytes) and re.fullmatch(b'(?:0x)?[0-9a-fA-F]{64}', raw), 'invalid original wallet encoding')
    value = raw[2:] if raw.startswith(b'0x') else raw
    require(0 < int(value, 16) < crypto.ORDER, 'invalid original wallet scalar')
    return value.lower()


def wallet(raw):
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    value = canonical(raw)
    public = ec.derive_private_key(int(value, 16), ec.SECP256K1()).public_key().public_bytes(
        Encoding.X962, PublicFormat.UncompressedPoint)
    return '0x' + crypto.keccak(public[1:])[-20:].hex()


def command(action, value):
    require(action in ('encrypt', 'decrypt') and isinstance(value, bytes) and len(value) <= 131072,
            'invalid credential transformation')
    args = ['/usr/bin/systemd-creds', action, '--name=' + NAME]
    if action == 'encrypt': args.append('--with-key=host')
    result = subprocess.run([*args, '-', '-'], input=value, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=30, check=False, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
    require(result.returncode == 0 and 0 < len(result.stdout) <= 131072, 'original wallet credential operation failed')
    return result.stdout


def origin(state, expected):
    state.owner(expected)
    value = state.get('key-origin.json')
    require(isinstance(value, dict) and set(value) == {'contract', 'wallet', 'plaintext_sha256'}
            and value['contract'] == expected and value['wallet'] == expected['wallet']
            and isinstance(value['plaintext_sha256'], str) and re.fullmatch('[0-9a-f]{64}', value['plaintext_sha256']),
            'original wallet custody authority differs')
    return value


def sealed(state, expected):
    original = origin(state, expected)
    receipt = state.get('key-current.json')
    require(isinstance(receipt, dict) and set(receipt) == {'origin', 'cipher_sha256'} and receipt['origin'] == original,
            'current wallet credential is not the original identity')
    directory(host.CUSTODY)
    cipher = read(host.CUSTODY / 'wallet.cred', 131072, mode=0o600)
    require(hashlib.sha256(cipher).hexdigest() == receipt['cipher_sha256'], 'current wallet ciphertext differs')
    return original, cipher


def inspect(state, expected, transform=command):
    original, cipher = sealed(state, expected)
    raw = canonical(transform('decrypt', cipher))
    require(hashlib.sha256(raw).hexdigest() == original['plaintext_sha256'] and wallet(raw) == expected['wallet'],
            'decrypted wallet is not the immutable original')
    return original


def import_original(state, expected, intent, raw, quiescent, restore=False, transform=command):
    return import_authorized(state,expected,intent,raw,lambda:state.pending(expected,intent),
                             quiescent,restore,transform)


def import_authorized(state, expected, intent, raw, authorize, safe_host, restore=False, transform=command):
    # Both callers hold the root operation lock. The deployment path requires a
    # stopped pending intent. Pre-stage instead proves a healthy observer or a
    # fenced/drained original restore, and never grants a runtime credential.
    require(type(restore) is bool, 'invalid original-wallet recovery request')
    authorize(); host.namespaces(); safe_host()
    value = canonical(raw)
    require(wallet(value) == expected['wallet'], 'concealed key does not belong to the original dedicated wallet')
    wanted = {'contract': expected, 'wallet': expected['wallet'], 'plaintext_sha256': hashlib.sha256(value).hexdigest()}
    path = state.root / 'key-origin.json'
    if path.exists():
        require(origin(state, expected) == wanted, 'original wallet cannot be changed')
        synchronize(path)
    else:
        require(not restore and not (state.root / 'key-current.json').exists()
                and not (state.root / 'signer-activated.json').exists(), 'original wallet metadata requires explicit recovery')
        require(not host.CUSTODY.exists() or not any(host.CUSTODY.iterdir()), 'orphan wallet material cannot be adopted')
        state.put('key-origin.json', wanted)
    if (state.root / 'key-current.json').exists() and not restore:
        inspect(state, expected, transform)
        return {'wallet': expected['wallet'], 'original_verified': True, 'changed': False}
    directory(host.CUSTODY, create=True, mode=0o700)
    require(host.CUSTODY.lstat().st_mode & 0o7777 == 0o700, 'original wallet custody directory is not private')
    # A stable operation directory recovers a visible encrypted payload after a
    # lost reply. It never generates another key or silently replaces ciphertext.
    stage = host.CUSTODY / ('import-' + intent)
    directory(stage, create=True, mode=0o700)
    require({p.name for p in stage.iterdir()} <= {'wallet.cred', 'receipt.json'}, 'unknown original-wallet staging material')
    cipher_path = stage / 'wallet.cred'
    if cipher_path.exists(): cipher = read(cipher_path, 131072, mode=0o600)
    else:
        cipher = transform('encrypt', value)
        write(cipher_path, cipher)
    require(canonical(transform('decrypt', cipher)) == value, 'original wallet encryption readback differs')
    receipt = {'origin': wanted, 'cipher_sha256': hashlib.sha256(cipher).hexdigest()}
    receipt_path = stage / 'receipt.json'
    if receipt_path.exists(): require(decode(read(receipt_path, mode=0o600)) == receipt, 'wallet staging receipt differs')
    else: write(receipt_path, encode(receipt))
    synchronize(cipher_path); synchronize(receipt_path); sync_directory(stage); sync_directory(host.CUSTODY)
    authorize(); safe_host()
    write(host.CUSTODY / 'wallet.cred', cipher)
    state.put('key-current.json', receipt)
    inspect(state, expected, transform)
    # Retain original encrypted generations, including after explicit recovery.
    return {'wallet': expected['wallet'], 'original_verified': True, 'changed': True}


def stage_runtime(state, expected, records, raw, quiescent):
    """Called as root after original-account and quiescence proofs, before exec."""
    require(state.guard(expected).get('phase') == 'active', 'wallet materialization requires active original authority')
    require(accounts.verify(state, expected) == records, 'runtime wallet account differs from original NSS')
    quiescent(records['node'])
    original = origin(state, expected)
    activated = state.get('signer-activated.json')
    require(activated.get('contract') == expected and activated.get('origin') == original
            and activated.get('history'), 'original signer/history activation is not durable')
    value = canonical(raw)
    require(hashlib.sha256(value).hexdigest() == original['plaintext_sha256'] and wallet(value) == expected['wallet'],
            'runtime credential differs from the original wallet')
    node = records['node']; group = node['gid']
    directory(host.RUNTIME, create=True, mode=0o755)
    private = host.RUNTIME / 'wallet'
    if not private.exists():
        private.mkdir(mode=0o700)
        os.chown(private, 0, group); os.chmod(private, 0o750)
        sync_directory(private); sync_directory(host.RUNTIME)
    directory(private)
    info = private.lstat()
    require(info.st_gid == group and info.st_mode & 0o7777 == 0o750, 'runtime wallet recipient directory changed')
    config = {'node': {'staker': {'parent-chain-wallet': {'private-key': value.decode('ascii')}}}}
    path = private / 'wallet.json'
    write(path, json.dumps(config, separators=(',', ':')).encode(), mode=0o440, group=group)
    info = path.lstat()
    require(info.st_uid == 0 and info.st_gid == group and info.st_mode & 0o7777 == 0o440,
            'runtime wallet credential was not published to the original numeric group')
    return path


def clear_runtime(records):
    path = host.RUNTIME/'wallet/wallet.json'
    if not path.exists() and not path.is_symlink(): return
    read(path, 131072, mode=0o440)
    require(path.lstat().st_gid == records['node']['gid'], 'runtime wallet recipient differs from retained original account')
    path.unlink(); sync_directory(path.parent)
