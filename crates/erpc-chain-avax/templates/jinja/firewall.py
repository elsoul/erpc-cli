#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Per-operation firewall confirmation. Apply already holds the remote run lock."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys


class Firewall:
    def __init__(self, root=Path('/'), run=subprocess.run):
        self.root, self.run = root, run
        self.directory = self.path('/etc/erpc/avax')

    def path(self, name):
        return self.root / name.lstrip('/')

    def command(self, *args, check=True):
        return self.run(list(args), check=check, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def read(self, name):
        return json.loads((self.directory / name).read_text())

    def write(self, name, content):
        path = self.directory / name
        temporary = path.with_suffix(path.suffix + '.new')
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)

    def contract(self):
        return json.loads(self.path('/etc/avalanchego/contract.json').read_text())

    @staticmethod
    def digest(data):
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def token(operation, bundle):
        if not re.fullmatch(r'r-[a-z0-9-]+', operation) or len(operation) > 80 or not re.fullmatch(r'[a-f0-9]{64}', bundle):
            raise ValueError('invalid firewall operation identity')
        return {'operation': operation, 'bundle': bundle}

    @staticmethod
    def timer(operation):
        return 'erpc-avax-firewall-rollback-' + operation

    def fingerprint(self):
        value = json.loads(self.command('nft', '-j', 'list', 'table', 'inet', 'erpc_avax').stdout)
        def normalize(item):
            if isinstance(item, dict):
                return {key: normalize(value) for key, value in item.items()
                        if key not in ('handle', 'packets', 'bytes', 'metainfo')}
            if isinstance(item, list):
                return [normalize(value) for value in item
                        if not (isinstance(value, dict) and 'metainfo' in value)]
            return item
        return self.digest(json.dumps(normalize(value), sort_keys=True).encode())

    def validate(self, record, filename):
        if record['contract'] != self.contract() or record['file'] != self.digest((self.directory / filename).read_bytes()):
            raise ValueError('firewall contract/file differs')
        if record['live'] != self.fingerprint():
            raise ValueError('live firewall rules differ')

    def apply(self, operation, bundle):
        expected = self.token(operation, bundle)
        run = self.path('/opt/erpc/runs/' + operation)
        if self.digest((run / 'bundle.tar.gz').read_bytes()) != bundle:
            raise ValueError('candidate is not from the requested immutable bundle')
        candidate = (run / 'bundle/firewall-candidate.nft').read_bytes()
        old_pending = self.directory / 'pending.json'
        if old_pending.exists():
            previous = self.read('pending.json')
            self.command('systemctl', 'stop', self.timer(previous['operation']) + '.timer', check=False)
            # Preserve the fallback from before the unconfirmed operation.
        else:
            live = self.command('nft', 'list', 'table', 'inet', 'erpc_avax', check=False)
            fallback = b'table inet erpc_avax\ndelete table inet erpc_avax\n' + live.stdout if live.returncode == 0 else b''
            self.write('previous.nft', fallback)
        self.write('pending.nft', candidate)
        record = dict(expected, contract=self.contract(), file=self.digest(candidate), live=None)
        self.write('pending.json', json.dumps(record).encode())
        self.command('systemd-run', '--quiet', '--collect', '--unit=' + self.timer(operation),
                     '--on-active=600', 'python3', '/usr/local/lib/erpc/avax-firewall.py',
                     'rollback', operation, bundle)
        self.command('nft', '-f', str(self.directory / 'pending.nft'))
        record['live'] = self.fingerprint()
        self.write('pending.json', json.dumps(record).encode())

    def confirm(self, operation, bundle):
        expected = self.token(operation, bundle)
        pending = self.directory / 'pending.json'
        if not pending.exists():
            # Retry is permitted only for this exact already confirmed operation.
            # A rollback to an older valid policy is never confirmation of this one.
            record = self.read('confirmed.json')
            if any(record[key] != value for key, value in expected.items()):
                raise ValueError('operation was rolled back or superseded')
            self.validate(record, 'firewall.nft')
            return
        record = self.read('pending.json')
        if any(record[key] != value for key, value in expected.items()):
            raise ValueError('operation was superseded')
        self.validate(record, 'pending.nft')
        self.command('systemctl', 'stop', self.timer(operation) + '.timer', check=False)
        self.write('firewall.nft', (self.directory / 'pending.nft').read_bytes())
        self.write('confirmed.json', json.dumps(record).encode())
        pending.unlink()
        (self.directory / 'pending.nft').unlink(missing_ok=True)

    def rollback(self, operation, bundle):
        expected = self.token(operation, bundle)
        pending = self.directory / 'pending.json'
        if not pending.exists():
            return
        record = self.read('pending.json')
        if any(record[key] != value for key, value in expected.items()):
            return  # A queued timer from an older run cannot roll back the new one.
        if record['contract'] != self.contract():
            raise ValueError('host ownership changed')
        fallback = self.directory / 'previous.nft'
        if fallback.exists() and fallback.stat().st_size:
            restored = self.command('nft', '-f', str(fallback), check=False)
            if restored.returncode:
                self.command('nft', 'delete', 'table', 'inet', 'erpc_avax', check=False)
        else:
            self.command('nft', 'delete', 'table', 'inet', 'erpc_avax', check=False)
        pending.unlink()
        (self.directory / 'pending.nft').unlink(missing_ok=True)

    def load(self):
        record = self.read('confirmed.json')
        if record['contract'] != self.contract() or record['file'] != self.digest((self.directory / 'firewall.nft').read_bytes()):
            raise ValueError('no matching confirmed boot policy')
        self.command('nft', '-f', str(self.directory / 'firewall.nft'))
        self.validate(record, 'firewall.nft')

    def dispatch(self, action, operation=None, bundle=None):
        if action == 'apply':
            # The embedded Ansible task runs under node-run.sh's /opt/erpc lock.
            self.apply(operation, bundle)
            return
        fd = os.open(self.path('/opt/erpc'), os.O_RDONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            if action == 'confirm': self.confirm(operation, bundle)
            elif action == 'rollback': self.rollback(operation, bundle)
            elif action == 'load': self.load()
            else: raise ValueError('unknown firewall operation')
        finally:
            os.close(fd)


if __name__ == '__main__':
    os.umask(0o077)
    try:
        Firewall().dispatch(*sys.argv[1:])
    except (ValueError, KeyError, OSError, TypeError, subprocess.SubprocessError):
        print('Avalanche firewall operation refused: operation, bundle, rules or ownership differ', file=sys.stderr)
        sys.exit(1)
