# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original Monad keystore bytes are secret, including with an empty native password.

Only systemd-encrypted copies persist on the host. Native recovery output contains
IKM/private keys: it is captured, parsed for exactly the public key and discarded.
"""
import base64
import os
from pathlib import Path
import re
import resource
import subprocess
from erpc_monad_common import (ENV, atomic, digest, execute, json_bytes, public_key, read,
                    require, unique_json, remove)

MAX_KEYSTORE = 4096


def keystore(data):
    require(isinstance(data, bytes) and 0 < len(data) <= MAX_KEYSTORE, 'invalid native keystore size')
    value = unique_json(data)
    require(isinstance(value, dict) and set(value) in (
        {'version', 'ciphertext', 'checksum', 'cipher', 'kdf', 'hash'},
        {'ciphertext', 'checksum', 'cipher', 'kdf', 'hash'}), 'invalid native keystore fields')
    require(type(value.get('version', 1)) is int and value.get('version', 1) in (1, 2), 'unsupported keystore version')
    hex_field = lambda x, size: isinstance(x, str) and re.fullmatch('[a-f0-9]{' + str(size * 2) + '}', x)
    require(hex_field(value['ciphertext'], 32) and hex_field(value['checksum'], 32)
            and value['hash'] == 'SHA256', 'invalid native ciphertext/checksum')
    cipher, kdf = value['cipher'], value['kdf']
    require(isinstance(cipher, dict) and set(cipher) == {'cipher_function', 'params'}
            and cipher['cipher_function'] == 'AES_128_CTR' and set(cipher['params']) == {'iv'}
            and hex_field(cipher['params']['iv'], 16), 'unsupported native cipher')
    require(isinstance(kdf, dict) and set(kdf) == {'kdf_name', 'params'} and kdf['kdf_name'] == 'scrypt',
            'unsupported native KDF')
    params = kdf['params']
    require(isinstance(params, dict) and set(params) == {'salt', 'key_len', 'N', 'r', 'p'}
            and hex_field(params['salt'], 32)
            and all(type(params.get(k)) is int and params[k] == v
                    for k, v in {'key_len': 32, 'N': 262144, 'r': 8, 'p': 1}.items()),
            'native KDF exceeds the qualified parameter bounds')
    return data


def parse_bundle(data, expected):
    require(len(data) <= 32768, 'concealed identity bundle exceeds limit')
    value = unique_json(data)
    require(isinstance(value, dict) and set(value) == {'schema', 'secp', 'bls'}
            and type(value['schema']) is int and value['schema'] == 1, 'invalid identity bundle')
    result = {}
    for kind in ('secp', 'bls'):
        item = value[kind]
        require(isinstance(item, dict) and set(item) == {'public_key', 'keystore_base64'},
                'invalid identity bundle member')
        require(public_key(item['public_key'], kind) == expected[kind], 'public identity differs from reservation')
        result[kind] = keystore(base64.b64decode(item['keystore_base64'], validate=True))
    require(result['secp'] != result['bls'], 'consensus roles require distinct native keystores')
    return result


def recover(data, kind, executable, uid, gid):
    """Run only a digest-qualified native tool. No private bytes reach its argv/env."""
    keystore(data)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    fd = os.memfd_create('erpc-monad-native', os.MFD_CLOEXEC)
    try:
        os.write(fd, data)
        os.lseek(fd, 0, os.SEEK_SET)
        env = dict(ENV, HOME='/nonexistent', LD_LIBRARY_PATH=str(executable.parent.parent / 'lib'))
        result = subprocess.run([str(executable), 'recover', '--keystore-path', '/proc/self/fd/' + str(fd),
                                 '--password', '', '--key-type', kind],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
                                pass_fds=(fd,), timeout=90, env=env, user=uid, group=gid, extra_groups=[], check=False)
        require(result.returncode == 0 and len(result.stdout) <= 8192 and len(result.stderr) <= 8192,
                'native identity verification failed; output withheld')
        label = b'Secp' if kind == 'secp' else b'BLS'
        values = re.findall(rb'^' + label + rb' public key: ([a-f0-9]+)$', result.stdout, re.M)
        require(len(values) == 1, 'native public identity was not uniquely reported')
        return public_key(values[0].decode('ascii'), kind)
    finally:
        os.close(fd)


def encrypt(data, kind):
    result = execute(['/usr/bin/systemd-creds', 'encrypt', '--with-key=host', '--name=monad-' + kind, '-', '-'], input_data=data)
    require(0 < len(result.stdout) <= 32768, 'invalid systemd encrypted credential')
    recovered = execute(['/usr/bin/systemd-creds', 'decrypt', '--name=monad-' + kind, '-', '-'],
                        input_data=result.stdout).stdout
    require(recovered == data, 'systemd credential readback differs')
    return result.stdout


def decrypt(cipher, kind):
    require(0 < len(cipher) <= 32768, 'invalid systemd credential size')
    return keystore(execute(['/usr/bin/systemd-creds', 'decrypt', '--name=monad-' + kind, '-', '-'],
                            input_data=cipher).stdout)


def import_once(directory, original, expected, verify, seal=encrypt):
    """The durable receipt includes both ciphertexts before either is published.

    A partial first import can resume its identical receipt. A completed receipt
    with a missing/substituted file requires explicit same-host restoration.
    """
    receipt = directory / 'identity.json'
    complete = directory / 'identity-complete'
    keys = parse_bundle(original, expected)
    if receipt.exists():
        saved = unique_json(read(receipt))
        require(saved['public'] == expected and all(saved[k]['plain_sha256'] == digest(keys[k])
                                                  for k in keys), 'original native identity bytes differ')
    else:
        require(not complete.exists() and not any(directory.glob('monad-*.cred')),
                'identity artifacts without an authoritative receipt')
        for kind, value in keys.items():
            require(verify(value, kind) == expected[kind], 'native public identity does not match')
        saved = {'public': expected}
        for kind, value in keys.items():
            cipher = seal(value, kind)
            saved[kind] = {'plain_sha256': digest(value), 'cipher_sha256': digest(cipher),
                           'cipher_base64': base64.b64encode(cipher).decode('ascii')}
        atomic(receipt, json_bytes(saved))
    for kind in keys:
        cipher = base64.b64decode(saved[kind]['cipher_base64'], validate=True)
        require(digest(cipher) == saved[kind]['cipher_sha256'], 'retained encrypted identity differs')
        path = directory / ('monad-' + kind + '.cred')
        if path.exists():
            require(read(path) == cipher, 'published identity differs; explicit restore required')
        else:
            require(not complete.exists(), 'established identity missing; explicit restore required')
            atomic(path, cipher)
    atomic(complete, b'complete\n')
    return saved


def check(directory, expected, verify, unseal=decrypt):
    require((directory / 'identity-complete').is_file() and not (directory / 'identity-restore-pending.json').exists(),
            'identity import or explicit restoration is incomplete')
    saved = unique_json(read(directory / 'identity.json'))
    require(saved['public'] == expected, 'identity receipt differs from reservation')
    for kind in ('secp', 'bls'):
        cipher = read(directory / ('monad-' + kind + '.cred'), 32768)
        require(digest(cipher) == saved[kind]['cipher_sha256'], 'encrypted native identity changed')
        original = unseal(cipher, kind)
        require(digest(original) == saved[kind]['plain_sha256'] and verify(original, kind) == expected[kind],
                'decrypted native identity changed')
    return saved


def restore(directory, original, expected, verify, seal=encrypt):
    """Explicitly reseal original native bytes after proving all writers stopped.

    The portable native keystore is unchanged. A new outer host credential may
    repair a lost/rotated systemd host key; previous ciphertexts remain retained.
    """
    saved = unique_json(read(directory / 'identity.json'))
    keys = parse_bundle(original, expected)
    require(saved['public'] == expected and all(digest(keys[k]) == saved[k]['plain_sha256'] for k in keys),
            'restore requires the original native keystore bytes and public identities')
    for kind, value in keys.items():
        require(verify(value, kind) == expected[kind], 'restored public identity differs')
    pending = directory / 'identity-restore-pending.json'
    if pending.exists():
        replacement = unique_json(read(pending))
        require(replacement['public'] == expected and all(digest(keys[k]) == replacement[k]['plain_sha256'] for k in keys),
                'interrupted restoration belongs to different native bytes')
    else:
        replacement = {'public': expected}
        for kind, value in keys.items():
            cipher = seal(value, kind)
            replacement[kind] = {'plain_sha256': digest(value), 'cipher_sha256': digest(cipher),
                                 'cipher_base64': base64.b64encode(cipher).decode('ascii')}
        # Receipt retains original outer ciphertexts as well as native file hashes.
        atomic(directory / ('identity-previous-' + digest(json_bytes(saved)) + '.json'), json_bytes(saved))
        atomic(pending, json_bytes(replacement))
    atomic(directory / 'identity.json', json_bytes(replacement))
    for kind in keys:
        cipher = base64.b64decode(replacement[kind]['cipher_base64'], validate=True)
        require(digest(cipher) == replacement[kind]['cipher_sha256'], 'retained restoration credential is corrupt')
        atomic(directory / ('monad-' + kind + '.cred'), cipher)
    atomic(directory / 'identity-complete', b'complete\n')
    remove(pending)
