#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original local P2P Ed25519 ciphertext; external consensus/funds keys never enter.

The native private-key flag still names the local libp2p identity when the
consensus signer is remote. Its key must be distinct from the remote public key.
"""
import base64

from arc_files import digest, require, strict_json
from av_files import ROOT
import av_accounts

CREDENTIAL = ROOT + '/consensus-key.cred'
STAGED = ROOT + '/consensus-key.staged'
RESTORE = ROOT + '/consensus-key.restore'
NAME = 'arc-validator-key'


def public(context, raw):
    # Same pinned Arc native format/RFC 8410 derivation as the reviewed RPC
    # custody profile; this dedicated profile owns different receipts/paths.
    require(isinstance(raw, bytes) and len(raw) <= 1024, 'invalid Arc validator identity envelope')
    value = strict_json(raw)
    require(isinstance(value, dict) and set(value) == {'type', 'value'} and
            value['type'] == 'tendermint/PrivKeyEd25519' and isinstance(value['value'], str),
            'invalid Arc validator native identity format')
    seed = bytearray(base64.b64decode(value['value'], validate=True))
    try:
        require(len(seed) == 32 and base64.b64encode(seed).decode() == value['value'],
                'Arc validator identity must contain its canonical original seed')
        result = context.command('/usr/bin/openssl', 'pkey', '-inform', 'DER', '-pubout', '-outform', 'DER',
                                 input=bytes.fromhex('302e020100300506032b657004220420') + seed, check=False)
        require(result.returncode == 0 and len(result.stdout) == 44 and
                result.stdout[:12] == bytes.fromhex('302a300506032b6570032100'),
                'Arc validator public identity derivation failed')
        return base64.b64encode(result.stdout[12:]).decode()
    finally:
        for index in range(len(seed)):
            seed[index] = 0
        # Python and subprocess copies are not claimed to be completely erased.


def decrypt(context, ciphertext):
    result = context.command('/usr/bin/systemd-creds', 'decrypt', '--name=' + NAME, '-', '-',
                             input=ciphertext, check=False)
    require(result.returncode == 0 and len(result.stdout) <= 1024,
            'Arc validator ciphertext cannot be opened on its original host')
    return result.stdout


def receipt(state):
    value = state.get('credential')
    require(isinstance(value, dict) and set(value) == {'ciphertext', 'sha256', 'public_key'} and
            value['public_key'] == state['contract']['peer_public_key'],
            'original Arc validator ciphertext receipt is absent or changed')
    raw = base64.b64decode(value['ciphertext'], validate=True)
    require(0 < len(raw) <= 16384 and base64.b64encode(raw).decode() == value['ciphertext'] and
            digest(raw) == value['sha256'], 'original Arc validator ciphertext receipt is invalid')
    return raw


def verified(context, state, prove=False):
    av_accounts.verify(state['accounts'])
    ciphertext = receipt(state)
    require(context.read(CREDENTIAL, limit=16384, private=True) == ciphertext,
            'Arc validator ciphertext is missing, replaced or no longer private')
    if prove:
        require(public(context, decrypt(context, ciphertext)) == state['contract']['peer_public_key'],
                'Arc validator ciphertext does not hold its original public identity')
    return ciphertext


def bind(state, ciphertext):
    return {'ciphertext': base64.b64encode(ciphertext).decode(), 'sha256': digest(ciphertext),
            'public_key': state['contract']['peer_public_key']}


def durable_original(context, state):
    av_accounts.verify(state['accounts'])
    context.save(state)
    context.sync(context.ROOT)


def encrypt(context, state, raw, staged):
    require(public(context, raw) == state['contract']['peer_public_key'],
            'supplied Arc validator key differs from its reserved original public identity')
    target = context.protected(staged, missing=True)
    if target.exists():
        ciphertext = context.read(staged, limit=16384, private=True, resync=True)
    else:
        result = context.command('/usr/bin/systemd-creds', 'encrypt', '--name=' + NAME, '-', '-',
                                 input=raw, check=False)
        require(result.returncode == 0 and 0 < len(result.stdout) <= 16384,
                'Arc validator identity encryption failed')
        ciphertext = result.stdout
        require(public(context, decrypt(context, ciphertext)) == state['contract']['peer_public_key'],
                'Arc validator encrypted key readback differs')
        context.write_bytes(staged, ciphertext)
    require(public(context, decrypt(context, ciphertext)) == state['contract']['peer_public_key'],
            'Arc validator staged identity differs from its original key')
    return ciphertext


def import_original(context, state, raw):
    context.assert_all_quiescent(state)
    durable_original(context, state)
    require(not state.get('signer_used') or state.get('credential') is not None,
            'used Arc validator identity cannot be initialized again')
    require(public(context, raw) == state['contract']['peer_public_key'],
            'supplied Arc validator key is not the reserved identity')
    if state.get('credential') is None:
        require(not context.protected(CREDENTIAL, missing=True).exists(),
                'receipt-free Arc validator ciphertext cannot be adopted')
        ciphertext = encrypt(context, state, raw, STAGED)
        state['credential'] = bind(state, ciphertext)
        durable_original(context, state)
    ciphertext = receipt(state)
    require(public(context, decrypt(context, ciphertext)) == state['contract']['peer_public_key'],
            'original Arc validator encrypted identity differs')
    if context.protected(CREDENTIAL, missing=True).exists():
        require(context.read(CREDENTIAL, limit=16384, private=True) == ciphertext,
                'different Arc validator ciphertext cannot be replaced implicitly')
    context.write_bytes(CREDENTIAL, ciphertext)
    verified(context, state)
    if context.protected(STAGED, missing=True).exists():
        require(context.read(STAGED, limit=16384, private=True) == ciphertext,
                'original staged Arc validator ciphertext changed')
        context.remove(STAGED)
    return {'public_key': state['contract']['peer_public_key'], 'custody': 'original'}


def restore_original(context, state, raw):
    context.assert_all_quiescent(state)
    context.assert_cancelled(state)
    durable_original(context, state)
    require(public(context, raw) == state['contract']['peer_public_key'],
            'restore cannot rotate the original Arc consensus key')
    original = receipt(state)
    context.mkdir(ROOT + '/cipher-history')
    previous = state.get('credential_replacement')
    existing = None
    if context.protected(CREDENTIAL, missing=True).exists():
        existing = context.read(CREDENTIAL, limit=16384, private=True)
        require(existing == original or (isinstance(previous, dict) and digest(existing) == previous['from']),
                'unknown existing Arc ciphertext is retained, not overwritten')
    for ciphertext in (original, existing):
        if ciphertext is None:
            continue
        destination = ROOT + '/cipher-history/' + digest(ciphertext) + '.cred'
        if context.protected(destination, missing=True).exists():
            require(context.read(destination, limit=16384, private=True) == ciphertext,
                    'retained original Arc ciphertext changed')
        context.write_bytes(destination, ciphertext)
    if previous is not None and not context.protected(RESTORE, missing=True).exists():
        # A completed target may be visible while removal of its staging file or
        # clearing the replacement receipt failed to reach stable storage.
        require(digest(original) == previous['to'], 'pending Arc restore lost its original target')
        context.write_bytes(RESTORE, original)
    replacement = encrypt(context, state, raw, RESTORE)
    target = digest(replacement)
    if previous is None:
        previous = {'from': digest(existing) if existing is not None else None, 'to': target}
    require(previous['to'] == target and (existing is None or digest(existing) in (previous['from'], target)),
            'pending Arc validator restore target changed')
    state['credential_replacement'] = previous
    state['credential'] = bind(state, replacement)
    durable_original(context, state)
    if context.protected(CREDENTIAL, missing=True).exists():
        require(digest(context.read(CREDENTIAL, limit=16384, private=True)) in (previous['from'], target),
                'Arc ciphertext changed during explicit restore')
    context.write_bytes(CREDENTIAL, replacement)
    verified(context, state)
    # Keep the completed replacement receipt with its target until the staged
    # file has durably disappeared, so either interruption resumes the same key.
    context.remove(RESTORE)
    state.pop('credential_replacement', None)
    durable_original(context, state)
    return {'public_key': state['contract']['peer_public_key'], 'custody': 'restored', 'started': False}
