#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""One original Ed25519 identity; recover the original encrypted capsule, never rotate it."""
import base64
import json
import os

from arc_files import Refused, digest, encoded, require, strict_json

CREDENTIAL = '/etc/credstore.encrypted/arc-consensus-key'
PENDING = '/etc/erpc/arc/authority/consensus-key.staged'


def public(c, raw):
    require(isinstance(raw, bytes) and len(raw) <= 1024, 'invalid Arc identity envelope')
    value = strict_json(raw)
    require(isinstance(value, dict) and set(value) == {'type', 'value'} and
            value['type'] == 'tendermint/PrivKeyEd25519' and isinstance(value['value'], str),
            'invalid Arc Ed25519 key format')
    try:
        seed = bytearray(base64.b64decode(value['value'], validate=True))
    except (ValueError, TypeError):
        raise Refused('invalid Arc key encoding') from None
    try:
        require(len(seed) == 32 and base64.b64encode(seed).decode() == value['value'],
                'Arc requires its original 32-byte canonical seed')
        # RFC 8410 PKCS#8 Ed25519 seed prefix. OpenSSL only derives the public key.
        der = bytes.fromhex('302e020100300506032b657004220420') + seed
        result = c.command('/usr/bin/openssl', 'pkey', '-inform', 'DER', '-pubout',
                           '-outform', 'DER', input=der, check=False)
        require(result.returncode == 0 and len(result.stdout) == 44 and
                result.stdout[:12] == bytes.fromhex('302a300506032b6570032100'),
                'Arc original public identity could not be derived')
        return base64.b64encode(result.stdout[12:]).decode()
    finally:
        for index in range(len(seed)):
            seed[index] = 0
        # Python/subprocess may retain copies; this does not claim complete RAM erasure.


def decrypt(c, ciphertext):
    result = c.command('/usr/bin/systemd-creds', 'decrypt', '--name=consensus-key', '-', '-',
                       input=ciphertext, check=False)
    require(result.returncode == 0 and len(result.stdout) <= 1024,
            'original Arc encrypted identity cannot be decrypted on this host')
    return result.stdout


def receipt(c, state, prove=False):
    record = state.get('credential')
    require(isinstance(record, dict) and set(record) == {'ciphertext', 'sha256', 'public_key'},
            'original Arc encrypted identity receipt is missing')
    try:
        cipher = base64.b64decode(record['ciphertext'], validate=True)
    except (ValueError, TypeError):
        raise Refused('invalid original Arc encrypted receipt') from None
    require(0 < len(cipher) <= 16384 and digest(cipher) == record['sha256'] and
            record['public_key'] == state['contract']['public_key'],
            'original Arc encrypted identity receipt changed')
    if prove:
        require(public(c, decrypt(c, cipher)) == record['public_key'],
                'original Arc decrypted identity differs')
    return cipher


def verify(c, state):
    cipher = receipt(c, state)
    require(c.read(CREDENTIAL, limit=16384, private=True) == cipher,
            'Arc credential is missing, substituted or not the original ciphertext')
    return {'credential': 'original'}


def materialize(c, state):
    cipher = receipt(c, state, prove=True)
    # Re-sync the original receipt even if a failed post-rename fsync left it visible.
    c.save(state)
    c.sync(c.ROOT)
    c.mkdir('/etc/credstore.encrypted')
    target = c.protected(CREDENTIAL, missing=True)
    if target.exists():
        require(c.read(CREDENTIAL, limit=16384, private=True) == cipher,
                'unrecognized Arc encrypted identity cannot be overwritten')
        c.read(CREDENTIAL, limit=16384, private=True, resync=True)
    else:
        c.write_bytes(CREDENTIAL, cipher)
    verify(c, state)
    staged = c.protected(PENDING, missing=True)
    if staged.exists():
        require(c.read(PENDING, limit=16384, private=True) == cipher,
                'Arc staged ciphertext differs from its original receipt')
        c.remove(PENDING)
    return {'credential': 'original', 'public_key': state['contract']['public_key']}


def import_original(c, state, raw):
    require(public(c, raw) == state['contract']['public_key'],
            'supplied Arc key is not the reserved original public identity')
    if state.get('credential') is not None:
        return materialize(c, state)
    require(not c.protected(CREDENTIAL, missing=True).exists(),
            'existing receipt-free Arc ciphertext requires explicit verified migration')
    staged = c.protected(PENDING, missing=True)
    if staged.exists():
        cipher = c.read(PENDING, limit=16384, private=True, resync=True)
        require(public(c, decrypt(c, cipher)) == state['contract']['public_key'],
                'staged Arc identity differs from the original reservation')
    else:
        result = c.command('/usr/bin/systemd-creds', 'encrypt', '--name=consensus-key', '-', '-',
                           input=raw, check=False)
        require(result.returncode == 0 and 0 < len(result.stdout) <= 16384,
                'Arc identity encryption failed')
        cipher = result.stdout
        require(public(c, decrypt(c, cipher)) == state['contract']['public_key'],
                'Arc identity encryption did not read back as the original')
        c.write_bytes(PENDING, cipher)
    state['credential'] = {'ciphertext': base64.b64encode(cipher).decode(),
                           'sha256': digest(cipher), 'public_key': state['contract']['public_key']}
    c.save(state)
    return materialize(c, state)


def restore_original(c, state, raw):
    """Explicit rewrap of the same key after shutdown, retaining every prior cipher."""
    require(public(c, raw) == state['contract']['public_key'], 'restore is not the original Arc identity')
    require(set(state.get('stopped', [])) == {'execution', 'consensus'}, 'Arc custody restore requires fenced services')
    original = receipt(c, state)
    c.mkdir('/etc/erpc/arc/authority/cipher-history')
    def retain(cipher):
        path = '/etc/erpc/arc/authority/cipher-history/' + digest(cipher) + '.cred'
        if c.protected(path, missing=True).exists():
            require(c.read(path, limit=16384, private=True) == cipher, 'original Arc cipher history changed')
        c.write_bytes(path, cipher)
    retain(original)
    existing = None
    if c.protected(CREDENTIAL, missing=True).exists():
        existing = c.read(CREDENTIAL, limit=16384, private=True)
        old_plan = state.get('credential_replacement')
        if existing != original:
            require(isinstance(old_plan, dict) and digest(existing) == old_plan.get('from') and
                    c.read('/etc/erpc/arc/authority/cipher-history/' + digest(existing) + '.cred', limit=16384, private=True) == existing,
                    'unknown Arc credential bytes are retained and cannot be overwritten')
        retain(existing)
    pending = '/etc/erpc/arc/authority/credential-restore.staged'
    if c.protected(pending, missing=True).exists():
        replacement = c.read(pending, limit=16384, private=True, resync=True)
        require(public(c, decrypt(c, replacement)) == state['contract']['public_key'],
                'staged Arc restore does not hold the same original key')
    else:
        result = c.command('/usr/bin/systemd-creds', 'encrypt', '--name=consensus-key', '-', '-', input=raw, check=False)
        require(result.returncode == 0 and 0 < len(result.stdout) <= 16384, 'Arc restore encryption failed')
        replacement = result.stdout
        require(public(c, decrypt(c, replacement)) == state['contract']['public_key'], 'Arc restore failed original key readback')
        c.write_bytes(pending, replacement)
    target = digest(replacement)
    plan = state.get('credential_replacement')
    if plan is not None:
        require(plan['to'] == target and (existing is None or digest(existing) in (plan['from'], plan['to'])),
                'Arc encrypted restore destination changed')
    else:
        plan = {'from': digest(existing) if existing else None, 'to': target}
        state['credential_replacement'] = plan
    state['credential'] = {'ciphertext': base64.b64encode(replacement).decode(), 'sha256': target,
                           'public_key': state['contract']['public_key']}
    c.save(state)
    c.sync(c.ROOT)
    # Recheck the exact old-or-completed destination after the durable replacement receipt.
    if c.protected(CREDENTIAL, missing=True).exists():
        require(digest(c.read(CREDENTIAL, limit=16384, private=True)) in (plan['from'], plan['to']),
                'Arc credential changed during explicit recovery')
    c.write_bytes(CREDENTIAL, replacement)
    verify(c, state)
    state.pop('credential_replacement', None)
    c.save(state)
    c.remove(pending)
    return {'credential': 'original', 'public_key': state['contract']['public_key']}
