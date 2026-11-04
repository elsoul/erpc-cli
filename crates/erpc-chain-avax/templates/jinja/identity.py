#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Persistent same-host identity guard. Never regenerate an established identity."""
import base64
import hashlib
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys
import time

ROOT = Path('/var/lib/avalanchego/staking')
NAMES = ('staker.crt', 'staker.key', 'signer.key')
MANIFEST = ROOT / 'identity.json'
AUTHORIZED = ROOT / 'generation-authorized'
STARTED = ROOT / 'generation-started'


def hashes():
    result = {}
    for name in NAMES:
        path = ROOT / name
        if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size < 65536:
            raise ValueError('missing or invalid staking identity')
        result[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def write(path, data):
    tmp = path.with_name(path.name + '.new')
    if tmp.exists() or tmp.is_symlink():
        tmp.unlink()
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    user = pwd.getpwnam('avalanchego')
    if os.geteuid() == 0:
        os.chown(tmp, user.pw_uid, user.pw_gid)
    os.replace(tmp, path)


def verify():
    if MANIFEST.is_symlink() or hashes() != json.loads(MANIFEST.read_text()):
        raise ValueError('staking identity differs from sealed manifest')


def main(action):
    if action == 'authorize':
        if MANIFEST.exists():
            verify()
        elif STARTED.exists() or any((ROOT / n).exists() for n in NAMES):
            raise ValueError('interrupted identity initialization; explicit recovery required')
        elif not AUTHORIZED.exists():
            write(AUTHORIZED, b'initial deployment only\n')
    elif action == 'guard':
        if MANIFEST.exists():
            verify()
        elif AUTHORIZED.exists() and not STARTED.exists() and not any((ROOT / n).exists() for n in NAMES):
            os.replace(AUTHORIZED, STARTED)
        else:
            raise ValueError('identity incomplete; automatic regeneration refused')
    elif action == 'seal':
        if MANIFEST.exists():
            verify()
            return
        if not STARTED.exists():
            raise ValueError('identity generation was not authorized')
        for _ in range(60):
            try:
                values = hashes()
                write(MANIFEST, json.dumps(values).encode())
                STARTED.unlink(missing_ok=True)
                return
            except (OSError, ValueError):
                time.sleep(1)
        raise ValueError('identity did not become complete')
    elif action == 'verify':
        verify()
    elif action == 'hashes':
        verify()
        print(json.dumps(hashes()))
    elif action == 'backup':
        verify()
        print(json.dumps({'hashes': hashes(), 'files': {n: base64.b64encode((ROOT / n).read_bytes()).decode() for n in NAMES}}))
    elif action == 'restore':
        # Recovery is only on the existing pinned host. Cross-host migration is
        # deliberately excluded: a local process check cannot fence another host.
        if subprocess.run(['systemctl', 'is-active', '--quiet', 'avalanchego']).returncode == 0:
            raise ValueError('stop AvalancheGo before identity recovery')
        if subprocess.run(['pgrep', '-u', 'avalanchego', '-x', 'avalanchego'], stdout=subprocess.DEVNULL).returncode == 0:
            raise ValueError('AvalancheGo process still running')
        payload = sys.stdin.buffer.read(262145)
        if len(payload) > 262144:
            raise ValueError('oversized identity bundle')
        envelope = json.loads(payload)
        if set(envelope) != {'expected_hashes', 'bundle'}:
            raise ValueError('invalid recovery envelope')
        data = envelope['bundle']
        if set(data) != {'hashes', 'files'} or set(data['files']) != set(NAMES):
            raise ValueError('invalid identity bundle')
        data['expected_hashes'] = envelope['expected_hashes']
        if data['hashes'] != data['expected_hashes']:
            raise ValueError('backup does not match pinned inventory identity')
        content = {n: base64.b64decode(data['files'][n], validate=True) for n in NAMES}
        if {n: hashlib.sha256(content[n]).hexdigest() for n in NAMES} != data['expected_hashes']:
            raise ValueError('identity backup digest mismatch')
        if MANIFEST.exists() and json.loads(MANIFEST.read_text()) != data['expected_hashes']:
            raise ValueError('existing identity manifest mismatch')
        for name in NAMES:
            path = ROOT / name
            if path.is_symlink() or (path.exists() and path.read_bytes() != content[name]):
                raise ValueError('refusing to overwrite a different identity')
        for name in NAMES:
            if not (ROOT / name).exists():
                write(ROOT / name, content[name])
        write(MANIFEST, json.dumps(data['expected_hashes']).encode())
        AUTHORIZED.unlink(missing_ok=True)
        STARTED.unlink(missing_ok=True)
        verify()
        print('identity restored; service remains stopped')
    else:
        raise ValueError('unknown identity action')

if __name__ == '__main__':
    try:
        main(sys.argv[1])
    except Exception:
        # Never include keys, parsed payload or subprocess output in errors.
        print('Avalanche identity operation refused; check sealed identity and recovery preconditions', file=sys.stderr)
        sys.exit(1)
