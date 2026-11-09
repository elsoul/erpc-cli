# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Closed original data policy, retained separately from new host/port policy.

Both qualified Agave pins distinguish data-shred retention from total-shred
retention. Never translate one flag's numeric value into the other's. Unknown
client features remain refused by the original public inspector.
"""
from pathlib import Path
import re
from native_files import atomic, encoded, read, require, root_directory, sync_directory, sync_file
import native_migration_inspect as original

DIRECTORY = Path('/var/lib/erpc-solana/migration-config')
OVERRIDES = DIRECTORY / 'overrides.yml'
VALUES = original.VALUES
NUMERIC = original.NUMERIC
SINGLES = original.SINGLES
CHANGES = original.CHANGES
settings = original.runtime_settings

def checked(value):
    require(isinstance(value, dict) and set(value) == {'schema', 'arguments', 'overrides', 'changes'}
            and type(value['schema']) is int and value['schema'] == 1, 'original runtime settings differ')
    # Reconstruct the narrowly allowed semantic fields and validate again.
    words = value['arguments']; require(isinstance(words, list) and len(words) <= 16, 'original runtime settings exceed their bound')
    options = {}; index = 0
    while index < len(words):
        key = words[index]; index += 1
        require(isinstance(key, str) and key in (*VALUES, *NUMERIC, *SINGLES) and key not in options,
                'unknown original runtime argument')
        item = True
        if key not in SINGLES:
            require(index < len(words), 'original runtime value is missing'); item = words[index]; index += 1
        options[key] = [item]
    mode = 'rpc'
    if value['overrides'] is not None: options['--staked-nodes-overrides'] = ['overrides.yml']
    extra = CHANGES + ['remove no-wait-for-vote-to-start-leader; retain native rooted-vote leader safety']
    require(value['changes'] in (CHANGES, extra), 'original plan changes differ')
    if value['changes'] == extra: options['--no-wait-for-vote-to-start-leader'] = [True]
    require(settings({'mode': mode, 'options': options, 'overrides': value['overrides']}) == value,
            'original runtime settings are not canonical')
    return value


def record(state, contract, scope, startup):
    expected = {'contract': contract, 'scope': scope, 'startup': startup, 'settings': settings(startup)}
    path = state.directory / 'migration-settings.json'
    if path.exists(): require(state.get(path.name) == expected, 'original migration policy changed')
    else: state.put(path.name, expected)
    sync_file(path); sync_directory(state.directory)
    return expected['settings']


def load(state, contract):
    owner = state.get('owner.json'); scope = owner.get('migration')
    path = state.directory / 'migration-settings.json'
    if scope is None:
        require(not path.exists() and not path.is_symlink(), 'orphan migration settings cannot be adopted'); return None
    require(state.migration_scope(contract, owner) == scope, 'original migration scope changed')
    value = state.get(path.name)
    require(set(value) == {'contract', 'scope', 'startup', 'settings'} and value['contract'] == contract
            and value['scope'] == scope and value['settings'] == settings(value['startup']),
            'original migration policy receipt differs')
    return checked(value['settings'])


def publish(value):
    checked(value)
    if value['overrides'] is None: return
    root_directory(DIRECTORY, create=True, mode=0o755)
    require(DIRECTORY.lstat().st_mode & 0o7777 == 0o755, 'native public configuration directory differs')
    require(all(path == OVERRIDES or re.fullmatch(r'\.erpc-[a-f0-9]{32}', path.name)
                for path in DIRECTORY.iterdir()), 'unowned native configuration exists')
    expected = value['overrides']['canonical_text'].encode('ascii')
    if OVERRIDES.exists() or OVERRIDES.is_symlink(): require(read(OVERRIDES) == expected, 'native original override was replaced')
    else: atomic(OVERRIDES, expected, 0o444)
    sync_file(OVERRIDES); sync_directory(DIRECTORY); verify(value)


def verify(value):
    checked(value)
    if value['overrides'] is not None:
        root_directory(DIRECTORY)
        require(DIRECTORY.lstat().st_mode & 0o7777 == 0o755 and OVERRIDES.lstat().st_mode & 0o7777 == 0o444
                and read(OVERRIDES) == value['overrides']['canonical_text'].encode('ascii'), 'native original public override differs')
