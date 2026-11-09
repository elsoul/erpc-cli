#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Append-only revocation evidence; partial files also invalidate older authority.

These events authorize lifecycle transitions, not consensus signing. No event is
rewritten or discarded. Explicit recovery archives mutable pending evidence
before replacing it; runtime grants bind the complete resulting history digest.
"""
import os
import re
import stat
from arc_files import digest, encoded, require, strict_json
from av_files import ROOT

DIRECTORY = ROOT + '/events'
KINDS = ('authorize', 'manual', 'stop', 'retire', 'pending-halt', 'pending-operation', 'pending-retired')
PATTERN = '(?:' + '|'.join(KINDS) + ')-[0-9a-f]{32}[.]event'
PENDING = tuple(ROOT + '/' + name + '.pending' for name in
                ('startup-revoked.json', 'operation.json', 'retired.json'))


def pending(context):
    return [name for name in PENDING if context.protected(name, missing=True).exists()]


def entries(context, durable=False):
    folder = context.protected(DIRECTORY, missing=True, directory=True)
    if not folder.exists():
        return []
    require(stat.S_IMODE(folder.stat().st_mode) == 0o700, 'lifecycle event directory is not private')
    names = sorted(os.listdir(folder))
    require(len(names) <= 100000, 'lifecycle history exceeds its bound')
    values = []
    for name in names:
        require(re.fullmatch(PATTERN, name), 'unknown lifecycle history artifact')
        # Empty/truncated contents remain restrictive evidence, never a grant.
        raw = context.read(DIRECTORY + '/' + name, private=True, limit=262144, resync=durable)
        values.append([name, digest(raw)])
    return values


def basis(context, durable=False):
    return digest(encoded(entries(context, durable)))


def retirement(context):
    names = [row for row in entries(context) if row[0].startswith(('retire-', 'pending-retired-'))]
    return digest(encoded(names)) if names else None


def pending_history(context):
    rows = [row for row in entries(context) if row[0].startswith('pending-')]
    return digest(encoded(rows)) if rows else None


def needs_recovery(context, state):
    return bool(pending(context)) or pending_history(context) != state.get('pending_recovery_ack')


def append(context, kind, raw, token=None):
    require(kind in KINDS and isinstance(raw, bytes) and len(raw) <= 262144, 'invalid lifecycle evidence')
    token = os.urandom(16).hex() if token is None else token
    require(re.fullmatch('[0-9a-f]{32}', token), 'invalid lifecycle event identity')
    folder = context.protected(DIRECTORY, missing=True, directory=True)
    if not folder.exists():
        context.mkdir(DIRECTORY)
    require(stat.S_IMODE(folder.stat().st_mode) == 0o700, 'lifecycle event directory is not private')
    path = context.protected(DIRECTORY + '/' + kind + '-' + token + '.event', missing=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == context.owner and info.st_nlink == 1 and
                stat.S_IMODE(info.st_mode) == 0o600, 'lifecycle event is not an original private file')
        view = memoryview(raw)
        while view:
            count = os.write(descriptor, view)
            require(count > 0, 'lifecycle event write made no progress')
            view = view[count:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    context.sync(context.path(DIRECTORY))
    return token


def archive_pending(context):
    names = pending(context)
    for name in names:
        kind = {'startup-revoked.json.pending': 'pending-halt',
                'operation.json.pending': 'pending-operation',
                'retired.json.pending': 'pending-retired'}[name.rsplit('/', 1)[1]]
        append(context, kind, context.read(name, private=True, limit=262144))
    # All copies must be durable before any original pending pathname disappears.
    for name in names:
        context.remove(name)


def retired_halt(context):
    for name in (ROOT + '/startup-revoked.json', ROOT + '/startup-revoked.json.pending'):
        if context.protected(name, missing=True).exists():
            raw = context.read(name, private=True, limit=262144)
            try:
                value = strict_json(raw)
            except (ValueError, UnicodeError):
                continue  # Unparseable evidence is retained by preserve(), never a grant.
            if isinstance(value, dict) and value.get('reason') == 'retired':
                return True
    return False


def preserve(context):
    # A prior destroy may have persisted only HALT while every other write
    # failed. Its committed reason is just as restrictive as its pending copy.
    halt = ROOT + '/startup-revoked.json'
    if context.protected(halt, missing=True).exists():
        raw = context.read(halt, private=True, limit=262144)
        try:
            value = strict_json(raw)
            reason = value.get('reason') if isinstance(value, dict) else None
        except (ValueError, UnicodeError):
            reason = None
        if reason not in ('new-deployment', 'stopped'):
            append(context, 'retire' if reason == 'retired' else 'pending-halt', raw)
    archive_pending(context)


def runtime(context, state):
    require(not pending(context) and isinstance(state.get('authorization_history'), str) and
            state['authorization_history'] == basis(context),
            'lifecycle cancellation or incomplete transition requires a fresh explicit recovery')
