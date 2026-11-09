# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original Solana identity custody using host-bound encrypted credentials.

Only identity keys are accepted. Vote-account and withdrawal keys are never
runtime inputs. The root caller holds the operation lock, fences the runtime,
and supplies the original key from the secret store over protected stdin.
"""
import hashlib
import os
from pathlib import Path
import re
import subprocess
from native_contract import KEYS, public_key, validate
from native_files import atomic, encoded, json_value, read, require, root_directory, sync_directory, sync_file
from native_state import token

CUSTODY = Path('/var/lib/erpc-solana/custody')
PKCS8 = bytes.fromhex('302e020100300506032b657004220420')
SPKI = bytes.fromhex('302a300506032b6570032100')


def native_command(argv, data, maximum):
    result = subprocess.run(argv, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=30, check=False, env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'})
    require(result.returncode == 0 and len(result.stdout) <= maximum,
            'native credential verification or encryption failed')
    return result.stdout


def public(seed):
    der = native_command(['/usr/bin/openssl', 'pkey', '-inform', 'DER', '-pubout', '-outform', 'DER'], PKCS8 + seed, 44)
    require(len(der) == 44 and der.startswith(SPKI), 'invalid Ed25519 public derivation')
    return der[len(SPKI):]


def base58(raw):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    number = int.from_bytes(raw, 'big'); result = ''
    while number:
        number, remainder = divmod(number, 58); result = alphabet[remainder] + result
    return '1' * (len(raw) - len(raw.lstrip(b'\x00'))) + result


def key_material(raw, expected):
    public_key(expected)
    require(isinstance(raw, bytes) and 0 < len(raw) <= 4096, 'invalid native identity size')
    value = json_value(raw)
    require(isinstance(value, list) and len(value) == 64
            and all(type(byte) is int and 0 <= byte <= 255 for byte in value), 'invalid native identity format')
    material = bytes(value)
    require(public(material[:32]) == material[32:] and base58(material[32:]) == expected,
            'native private identity does not match the reserved public identity')
    return encoded(value)


def crypt(action, data):
    require(action in ('encrypt', 'decrypt'), 'invalid native credential action')
    args = ['/usr/bin/systemd-creds', action, '--name=identity']
    if action == 'encrypt': args.append('--with-key=host')
    return native_command([*args, '-', '-'], data, 1048576 if action == 'encrypt' else 4096)


def private(path):
    root_directory(path.parent)
    require(path.lstat().st_mode & 0o7777 == 0o600, 'native encrypted identity is not private')
    return read(path, 1048576)


def resume(state, contract, role):
    state.owner(contract)
    require(role in ('sync', 'validator', 'rpc')
            and (role == 'rpc') == (contract['profile'] == 'agave-native-rpc'), 'invalid native identity role')
    receipt = state.get('identity-' + role + '.json')
    require(set(receipt) == {'contract', 'role', 'public', 'plaintext_sha256', 'cipher_sha256', 'pending'}
            and receipt['contract'] == contract and receipt['role'] == role
            and re.fullmatch(role + r'-[a-f0-9]{32}\.pending\.cred', receipt['pending']),
            'native identity receipt scope differs')
    for name in ('plaintext_sha256', 'cipher_sha256'):
        require(isinstance(receipt[name], str) and re.fullmatch('[a-f0-9]{64}', receipt[name]),
                'invalid native identity receipt')
    public_key(receipt['public'])
    root_directory(CUSTODY)
    pending, target = CUSTODY / receipt['pending'], CUSTODY / (role + '.cred')
    sync_file(state.directory / ('identity-' + role + '.json')); sync_directory(state.directory)
    if pending.exists() or pending.is_symlink():
        require(hashlib.sha256(private(pending)).hexdigest() == receipt['cipher_sha256'],
                'interrupted encrypted identity differs')
        sync_file(pending); sync_directory(CUSTODY); sync_directory(CUSTODY.parent)
        os.replace(pending, target)
    require(hashlib.sha256(private(target)).hexdigest() == receipt['cipher_sha256'],
            'original encrypted identity is missing or changed')
    # A visible successful rename is not a durable success until both the
    # ciphertext and its namespace and the receipt are synchronized again.
    sync_file(target); sync_directory(CUSTODY)
    sync_file(state.directory / ('identity-' + role + '.json')); sync_directory(state.directory)
    return receipt


def retain(path, raw, kind='previous'):
    require(kind in ('previous', 'unrecognized'), 'invalid retained credential classification')
    digest = hashlib.sha256(raw).hexdigest()
    previous = CUSTODY / (path.stem + '.' + kind + '.' + digest + '.cred')
    if previous.exists() or previous.is_symlink():
        require(private(previous) == raw, 'retained native encrypted generation differs')
    else:
        atomic(previous, raw)
    # Fresh inode, never a hardlink into the single-link credential namespace.
    sync_file(previous); sync_directory(CUSTODY)


def complete(state, contract, role):
    receipt = resume(state, contract, role)
    name = 'identity-import-' + role + '.json'
    if (state.directory / name).exists():
        pending = state.get(name)
        require(all(pending[key] == receipt[key] for key in ('contract', 'role', 'public', 'plaintext_sha256', 'pending')),
                'interrupted native identity operation differs from its receipt')
        state.remove(name)
    return receipt


def import_identity(state, contract, intent, role, raw, expected, quiescent, restore=False):
    validate(contract); token(intent)
    require(role in ('sync', 'validator', 'rpc') and type(restore) is bool
            and (role == 'rpc') == (contract['profile'] == 'agave-native-rpc'), 'invalid native identity role')
    public_key(expected)
    require((role in ('validator', 'rpc') and expected == contract['identity_account'])
            or (role == 'sync' and expected not in [contract[name] for name in KEYS]),
            'native identity is not authorized for this role')
    pending = state.current(contract, intent)
    require(pending['target'].get('mode') == role and pending['target'].get('identity') == expected,
            'identity delivery differs from the explicitly authorized runtime target')
    cutover = state.get('cutover.json')
    require(all(cutover[key] == pending[key] for key in ('intent', 'halt', 'target')),
            'native identity import requires the current fenced cutover')
    def authorize():
        current = state.current(contract, intent)
        require(current == pending and state.get('cutover.json') == cutover,
                'native identity delivery lost its original cutover authority')
    return retain_original(state, contract, intent, role, raw, expected, quiescent, authorize, restore)


def retain_original(state, contract, intent, role, raw, expected, quiescent, authorize, restore=False):
    """Publish original ciphertext under an explicit caller-owned custody fence.

    Runtime delivery uses the original deployment cutover. Copy migration uses
    the still-closed migration marker plus original stopped-source proof. This
    function creates neither authorization nor native runtime activation.
    """
    validate(contract); token(intent)
    require(role in ('sync','validator','rpc') and type(restore) is bool
            and (role == 'rpc') == (contract['profile'] == 'agave-native-rpc'), 'invalid native custody role')
    require((role in ('validator','rpc') and expected == contract['identity_account'])
            or (role == 'sync' and expected not in [contract[name] for name in KEYS]),
            'native custody does not match its original role')
    authorize(); quiescent()
    canonical = key_material(raw, expected)
    plain_digest = hashlib.sha256(canonical).hexdigest()
    root_directory(CUSTODY, create=True, mode=0o700)
    sync_directory(CUSTODY); sync_directory(CUSTODY.parent)
    receipt_name = 'identity-' + role + '.json'
    target = CUSTODY / (role + '.cred')
    original = None
    if (state.directory / receipt_name).exists():
        original = state.get(receipt_name)
        require(original['contract'] == contract and original['role'] == role
                and original['public'] == expected and original['plaintext_sha256'] == plain_digest,
                'only the original native identity can be restored')
        if not restore or original['pending'] == role + '-' + intent + '.pending.cred':
            return complete(state, contract, role)
    else:
        require(not restore and not target.exists() and not target.is_symlink(),
                'unreceipted native credential cannot be adopted or restored')
    import_name = 'identity-import-' + role + '.json'
    operation = {'contract': contract, 'intent': intent, 'role': role, 'public': expected,
                 'plaintext_sha256': plain_digest, 'restore': restore,
                 'pending': role + '-' + intent + '.pending.cred'}
    if (state.directory / import_name).exists():
        require(state.get(import_name) == operation, 'another native key import is incomplete')
    else:
        state.put(import_name, operation)
    # Re-establish the visible intent before encrypting or publishing anything.
    sync_file(state.directory / import_name); sync_directory(state.directory)
    candidate = CUSTODY / operation['pending']
    if candidate.exists() or candidate.is_symlink():
        encrypted = private(candidate)
        require(key_material(crypt('decrypt', encrypted), expected) == canonical,
                'interrupted native ciphertext does not contain the original identity')
    else:
        encrypted = crypt('encrypt', canonical)
        require(encrypted and key_material(crypt('decrypt', encrypted), expected) == canonical,
                'native encrypted identity failed its read-back')
        atomic(candidate, encrypted)
    if original is not None and (target.exists() or target.is_symlink()):
        old = private(target)
        # Explicit restore already proved the exact original private identity.
        # Preserve corrupted/unknown bytes separately; never adopt them as a key.
        kind = 'previous' if hashlib.sha256(old).hexdigest() == original['cipher_sha256'] else 'unrecognized'
        retain(target, old, kind)
    quiescent(); authorize()
    receipt = {key: operation[key] for key in ('contract', 'role', 'public', 'plaintext_sha256', 'pending')}
    receipt['cipher_sha256'] = hashlib.sha256(encrypted).hexdigest()
    state.put(receipt_name, receipt)
    return complete(state, contract, role)
