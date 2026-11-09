# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Sealed complete helper-profile publication while original runtime is fenced."""
import hashlib
import os
from pathlib import Path
import re
import host
import protocol
from storage import directory, read, require, sync_directory, write


def profile(source):
    directory(source)
    files = {}
    for path in sorted(source.iterdir(), key=lambda value: value.name):
        require(re.fullmatch('[a-z][a-z0-9_]*\\.py', path.name), 'helper profile contains an unsupported entry')
        files[path.name] = read(path, 8*1024*1024)
    require({'control.py', 'entry.py', 'upstreams.py'} <= set(files), 'validator helper profile is incomplete')
    digest = hashlib.sha256()
    for name, contents in files.items(): digest.update(name.encode()+b'\0'+hashlib.sha256(contents).digest())
    return digest.hexdigest(), files


def publish(state, expected, intent, source, quiet):
    pending = state.pending(expected, intent); target = pending['target']
    host.namespaces(); quiet()
    digest, files = profile(source); protocol.target(target, digest)
    directory(host.HELPERS, create=True, mode=0o755)
    require(host.HELPERS.lstat().st_mode & 0o7777 == 0o755, 'installed helper directory must remain traversable')
    # The independent stopped fence remains authoritative across every copy.
    # A failed partial publication is recovered only by the sealed carried entry.
    require({path.name for path in host.HELPERS.iterdir()} <= set(files),
            'unknown installed helper cannot be silently removed or adopted')
    for name, contents in files.items(): write(host.HELPERS/name, contents, mode=0o644)
    for old in host.HELPERS.iterdir():
        require(old.name in files, 'unknown installed helper cannot be silently removed or adopted')
    sync_directory(host.HELPERS)
    require(profile(host.HELPERS)[0] == digest, 'published helper profile differs from the carried source')
    state.pending(expected, intent); quiet()
    state.put('helpers.json', {'contract': expected, 'sha256': digest})
    return {'helpers_sha256': digest, 'published': True}


def verify(state, expected, target):
    state.owner(expected); host.namespaces()
    require(state.get('helpers.json') == {'contract': expected, 'sha256': target['helpers_sha256']}
            and profile(host.HELPERS)[0] == target['helpers_sha256'], 'installed helper profile is incomplete or changed')
