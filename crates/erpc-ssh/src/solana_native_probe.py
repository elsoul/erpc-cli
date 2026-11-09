# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Public ownership probe; never reads credentials or a legacy user's home."""
import json
import os
from pathlib import Path
import re
import stat
import sys


def unique(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result: raise ValueError('duplicate field')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def read(path):
    for parent in reversed(path.parents):
        try: info = parent.lstat()
        except FileNotFoundError: return None
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('unsafe native state ancestor')
    try: descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError: return None
    with os.fdopen(descriptor, 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o077:
            raise ValueError('unsafe native state file')
        raw = source.read(65537)
        if len(raw) > 65536: raise ValueError('native state is too large')
        value = unique(raw)
        if not isinstance(value, dict): raise ValueError('native state is not an object')
        return value


try:
    raw = sys.stdin.buffer.read(65537)
    if len(raw) > 65536: raise ValueError('request is too large')
    request = unique(raw)
    if not isinstance(request, dict) or set(request) != {'contract'} or not isinstance(request['contract'], dict):
        raise ValueError('invalid ownership request')
    directory = Path('/var/lib/erpc-solana/state')
    owner = read(directory / 'owner.json')
    migration = read(directory / 'migration.json')
    if migration is not None:
        scope=migration.get('scope')
        if (set(migration)!={'contract','scope','phase'} or migration['contract']!=request['contract']
                or migration['phase'] not in ('preparing','complete') or not isinstance(scope,dict)
                or set(scope)!={'intent','source_sha256'}
                or not isinstance(scope['intent'],str) or not re.fullmatch('[a-f0-9]{32}',scope['intent'])
                or not isinstance(scope['source_sha256'],str) or not re.fullmatch('[a-f0-9]{64}',scope['source_sha256'])
                or owner is not None and owner.get('migration')!=scope):
            raise ValueError('original migration ownership differs')
        if owner is None and migration['phase']=='complete':raise ValueError('completed migration lacks native ownership')
    elif owner is not None and 'migration' in owner:
        raise ValueError('original migration receipt is missing')
    if owner is None:
        result = {'reserved': False, 'initialized': False, 'helper_revision': None}
    else:
        if owner['contract'] != request['contract'] or type(owner['initialized']) is not bool:
            raise ValueError('native host ownership differs')
        helper = read(directory / 'helper-revision.json')
        revision = None if helper is None else helper.get('revision')
        if revision is not None and (not isinstance(revision, str) or not re.fullmatch('[a-f0-9]{64}', revision)):
            raise ValueError('invalid native helper metadata')
        result = {'reserved': True, 'initialized': owner['initialized'], 'helper_revision': revision}
    if migration is not None:
        result['migration_phase']=migration['phase']
        result['reserved']=True
        if migration['phase']!='complete':result.update(initialized=False,helper_revision=None)
    print(json.dumps(result, separators=(',', ':')))
except Exception:
    print('Native Solana ownership inspection failed', file=sys.stderr)
    raise SystemExit(1)
