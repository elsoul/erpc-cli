# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Public address and native V3 keystore verification; never signs a transaction."""
import hashlib
import hmac
import json
from pathlib import Path
import re
import subprocess
import tempfile

ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
JAVA = {
    'x86_64': '/usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java',
    'aarch64': '/usr/lib/jvm/java-17-openjdk-arm64/bin/java',
}


def address(value):
    if not isinstance(value, str) or len(value) != 34 or not value.startswith('T'):
        raise ValueError('expected a canonical TRON Base58Check public address')
    number = 0
    for character in value:
        number = number * 58 + ALPHABET.index(character)
    raw = number.to_bytes(25, 'big')
    checksum = hashlib.sha256(hashlib.sha256(raw[:21]).digest()).digest()[:4]
    if raw[0] != 65 or not hmac.compare_digest(raw[21:], checksum):
        raise ValueError('invalid TRON address checksum or prefix')
    return raw[:21]


def hex_value(value, size):
    if not isinstance(value, str) or not re.fullmatch('[a-fA-F0-9]{' + str(size * 2) + '}', value):
        raise ValueError('invalid native keystore byte encoding')
    return bytes.fromhex(value)


def bounded_integer(value, lower, upper):
    if type(value) is not int or not lower <= value <= upper:
        raise ValueError('native keystore KDF exceeds supported resource bounds')
    return value


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON field is refused')
        result[key] = value
    return result


def keystore(text, expected):
    """Reject hidden key fields and unbounded KDF requests before native decoding."""
    address(expected)
    if len(text) > 16384:
        raise ValueError('native keystore exceeds 16 KiB')
    value = json.loads(text, object_pairs_hook=unique_object)
    if not isinstance(value, dict) or set(value) - {'version', 'address', 'id', 'crypto'}:
        raise ValueError('only the public native encrypted keystore schema is accepted')
    if type(value.get('version')) is not int or value['version'] != 3 or value.get('address') != expected:
        raise ValueError('keystore version or declared signing address differs')
    if 'id' in value and (not isinstance(value['id'], str) or not re.fullmatch(
            '[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}', value['id'])):
        raise ValueError('native keystore identifier is not a UUID')
    crypto = value['crypto']
    if not isinstance(crypto, dict) or set(crypto) != {'cipher', 'ciphertext', 'cipherparams', 'kdf', 'kdfparams', 'mac'}:
        raise ValueError('invalid native keystore structure')
    if crypto['cipher'] != 'aes-128-ctr' or set(crypto['cipherparams']) != {'iv'}:
        raise ValueError('unsupported native keystore cipher')
    hex_value(crypto['cipherparams']['iv'], 16)
    hex_value(crypto['ciphertext'], 32)
    hex_value(crypto['mac'], 32)
    params = crypto['kdfparams']
    if not isinstance(params, dict) or params.get('dklen') != 32 or type(params.get('dklen')) is not int:
        raise ValueError('unsupported native keystore derived-key size')
    hex_value(params['salt'], 32)
    if crypto['kdf'] == 'scrypt':
        if set(params) != {'dklen', 'n', 'r', 'p', 'salt'}:
            raise ValueError('invalid scrypt parameters')
        n = bounded_integer(params['n'], 2, 1 << 20)
        r = bounded_integer(params['r'], 1, 32)
        p = bounded_integer(params['p'], 1, 32)
        if n & (n - 1) or 128 * n * r > 512 * 1024 * 1024 or n * r * p > 1 << 24:
            raise ValueError('scrypt memory/work exceeds the reviewed bound')
    elif crypto['kdf'] == 'pbkdf2':
        if set(params) != {'dklen', 'c', 'prf', 'salt'} or params['prf'] != 'hmac-sha256':
            raise ValueError('unsupported PBKDF2 parameters')
        bounded_integer(params['c'], 1, 2000000)
    else:
        raise ValueError('unsupported native keystore KDF')
    return value


def inspect(text, password, expected, architecture, run=subprocess.run, temporary=tempfile.TemporaryDirectory):
    keystore(text, expected)
    if not isinstance(password, str) or len(password.encode('utf-16-le')) < 12 or len(password.encode()) > 1024:
        raise ValueError('native keystore password has an unsupported size')
    if any(c in password for c in ('\n', '\r', '\0')) or password.startswith('\ufeff'):
        raise ValueError('native password must be a single exact line without BOM')
    java = JAVA[architecture]
    with temporary(prefix='tron-key-check-', dir='/run') as directory:
        encrypted = Path(directory) / 'witness.json'
        encrypted.write_text(text)
        result = run([
            java, '-XX:-HeapDumpOnOutOfMemoryError', '-XX:ErrorFile=/dev/null',
            '-Dlogback.configurationFile=/etc/tron/quiet-logback.xml',
            '-cp', '/opt/tron/current/FullNode.jar:/opt/tron/current/erpc',
            'ErpcTronKey', str(encrypted),
        ], input=(password + '\n').encode(), stdout=subprocess.PIPE,
           stderr=subprocess.DEVNULL, check=False, timeout=120,
           env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'})
        if result.returncode or result.stdout.decode().strip() != expected:
            raise ValueError('native keystore authentication or derived public address failed')
    return expected
