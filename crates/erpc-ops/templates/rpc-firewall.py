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
    def __init__(self, family, root=Path('/'), run=subprocess.run):
        if family not in ('eth', 'arc', 'solana-rpc', 'optimism', 'base', 'soneium', 'arbitrum', 'robinhood', 'near', 'tron'):
            raise ValueError('unsupported firewall family')
        self.family = family
        self.table = 'erpc_' + family.replace('-', '_')
        self.root, self.run = root, run
        self.directory = self.path('/etc/erpc/' + family)

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
        return self.family

    @staticmethod
    def digest(data):
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def token(operation, bundle):
        if not re.fullmatch(r'r-[a-z0-9-]+', operation) or len(operation) > 80 or not re.fullmatch(r'[a-f0-9]{64}', bundle):
            raise ValueError('invalid firewall operation identity')
        return {'operation': operation, 'bundle': bundle}

    def timer(self, operation):
        return 'erpc-' + self.family + '-firewall-rollback-' + operation

    def fingerprint(self):
        value = json.loads(self.command('nft', '-j', 'list', 'table', 'inet', self.table).stdout)
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
        self.prepare_guards()
        self.write('startup-revoked', b'policy transition')
        old_pending = self.directory / 'pending.json'
        if old_pending.exists():
            previous = self.read('pending.json')
            self.command('systemctl', 'stop', self.timer(previous['operation']) + '.timer', check=False)
            # Preserve the fallback from before the unconfirmed operation.
        else:
            live = self.command('nft', 'list', 'table', 'inet', self.table, check=False)
            fallback = ('table inet ' + self.table + '\ndelete table inet ' + self.table + '\n').encode() + live.stdout if live.returncode == 0 else b''
            self.write('previous.nft', fallback)
        self.write('pending.nft', candidate)
        record = dict(expected, contract=self.contract(), file=self.digest(candidate), live=None)
        self.write('pending.json', json.dumps(record).encode())
        self.command('systemd-run', '--quiet', '--collect', '--unit=' + self.timer(operation),
                     '--on-active=120', 'python3', '/usr/local/lib/erpc/rpc-firewall.py',
                     self.family, 'rollback', operation, bundle)
        self.command('nft', '-f', str(self.directory / 'pending.nft'))
        record['live'] = self.fingerprint()
        self.write('pending.json', json.dumps(record).encode())
        (self.directory / 'startup-revoked').unlink(missing_ok=True)

    def confirm(self, operation, bundle):
        if (self.directory / 'startup-revoked').exists():
            raise ValueError('startup authorization revoked')
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

    def services(self):
        return {
            'eth': ['reth.service', 'lighthouse.service', 'reth-snapshot.service'],
            'arc': ['arc-execution.service', 'arc-consensus.service', 'arc-snapshots.service'],
            'solana-rpc': ['solv.service', 'faithful.service', 'of1-index-sync.service'],
            'near': ['near-node.service'],
            'tron': ['tron-node.service'],
            **{family: ['erpc-' + family + '-' + unit + '.service' for unit in
                       ('execution', 'consensus', 'upstreams', 'rpc', 'bootstrap')]
               for family in ('optimism', 'base', 'soneium')},
            **{family: ['erpc-' + family + '-nitro.service', 'erpc-' + family + '-upstreams.service']
               for family in ('arbitrum', 'robinhood')},
        }[self.family]

    def guard_config(self):
        return ('[Unit]\nRequires=erpc-' + self.family + '-firewall.service\n'
                'After=erpc-' + self.family + '-firewall.service\n'
                '[Service]\nExecStartPre=+/usr/bin/python3 /usr/local/lib/erpc/rpc-firewall.py '
                + self.family + ' guard\n')

    def prepare_guards(self):
        # Protect already-installed units as well as units a later phase creates.
        for service in self.services():
            directory = self.path('/etc/systemd/system/' + service + '.d')
            if directory.is_symlink():
                raise ValueError('refuse an indirect managed service override directory')
            directory.mkdir(parents=True, exist_ok=True, mode=0o755)
            path = directory / '50-erpc-firewall-guard.conf'
            pending = directory / '50-erpc-firewall-guard.conf.new'
            pending.write_text(self.guard_config())
            os.chmod(pending, 0o644)
            os.replace(pending, path)
        self.command('systemctl', 'daemon-reload')

    def require_guards(self):
        for service in self.services():
            path = self.path('/etc/systemd/system/' + service + '.d/50-erpc-firewall-guard.conf')
            if path.is_symlink() or path.read_text() != self.guard_config():
                raise ValueError('listener startup guard is missing or changed; keep filtering')

    def stop_unfiltered_services(self):
        self.require_guards()
        self.write('startup-revoked', b'filter removal fenced startup')
        services = self.services() + (['of1-index-sync.timer'] if self.family == 'solana-rpc' else [])
        # No fallback policy: prevent current listeners and reboot auto-start
        # before removing the table. A failed stop leaves filtering in place.
        present = []
        for service in services:
            found = self.command('systemctl', 'show', '--property=LoadState', '--value', service, check=False)
            state = found.stdout.decode().strip()
            if state == 'not-found':
                continue
            if found.returncode != 0 or state not in ('loaded', 'masked'):
                raise ValueError('cannot establish the service state before removing filtering')
            present.append(service)
        if present:
            self.command('systemctl', 'disable', '--now', *present)

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
                self.stop_unfiltered_services()
                self.command('nft', 'delete', 'table', 'inet', self.table, check=False)
        else:
            self.stop_unfiltered_services()
            self.command('nft', 'delete', 'table', 'inet', self.table, check=False)
        pending.unlink()
        (self.directory / 'pending.nft').unlink(missing_ok=True)

    def teardown(self):
        # The destroy play owns /opt/erpc. Retrofit legacy units before stopping.
        self.prepare_guards()
        self.stop_unfiltered_services()
        if (self.directory / 'pending.json').exists():
            record = self.read('pending.json')
            self.command('systemctl', 'stop', self.timer(record['operation']) + '.timer', check=False)
            (self.directory / 'pending.json').unlink()
        self.command('nft', 'delete', 'table', 'inet', self.table, check=False)
        (self.directory / 'pending.nft').unlink(missing_ok=True)

    def guard(self):
        if (self.directory / 'startup-revoked').exists():
            raise ValueError('startup authorization revoked')
        # Read-only: may run as a systemd dependency while Ansible owns the lock.
        for name, policy in [('pending.json', 'pending.nft'), ('confirmed.json', 'firewall.nft')]:
            try:
                self.validate(self.read(name), policy)
                return
            except (ValueError, KeyError, OSError, TypeError, subprocess.SubprocessError):
                continue
        raise ValueError('no matching live policy permits node startup')

    def load(self):
        if (self.directory / 'startup-revoked').exists():
            raise ValueError('startup authorization revoked')
        record = self.read('confirmed.json')
        policy = self.directory / 'firewall.nft'
        if record['contract'] != self.contract() or record['file'] != self.digest(policy.read_bytes()):
            raise ValueError('no matching confirmed boot policy')
        self.command('nft', '-f', str(policy))
        self.validate(record, 'firewall.nft')
        # Boot recovery to the last confirmed policy supersedes an interrupted run.
        (self.directory / 'pending.json').unlink(missing_ok=True)
        (self.directory / 'pending.nft').unlink(missing_ok=True)

    def require_confirmed(self, operation, bundle):
        expected = self.token(operation, bundle)
        if (self.directory / 'startup-revoked').exists() or (self.directory / 'pending.json').exists():
            raise ValueError('preparation was revoked or superseded')
        record = self.read('confirmed.json')
        if any(record[key] != value for key, value in expected.items()):
            raise ValueError('confirmed preparation belongs to another operation')
        self.validate(record, 'firewall.nft')

    def dispatch(self, action, operation=None, bundle=None):
        if action in ('guard', 'load'):
            if (self.directory / 'startup-revoked').exists():
                raise ValueError('startup authorization revoked')
            try:
                self.guard()
                return
            except (ValueError, KeyError, OSError, TypeError, subprocess.SubprocessError):
                if action == 'guard':
                    raise
        if action == 'require-confirmed':
            # The deployment play already owns the common operation lock.
            self.require_confirmed(operation, bundle)
            return
        if action == 'teardown':
            self.teardown()
            return
        if action == 'apply':
            # The embedded Ansible task runs under node-run.sh's /opt/erpc lock.
            self.apply(operation, bundle)
            return
        fd = os.open(self.path('/opt/erpc'), os.O_RDONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | (fcntl.LOCK_NB if action == 'load' else 0))
            if action == 'confirm':
                self.confirm(operation, bundle)
                print('firewall=confirmed')
            elif action == 'rollback': self.rollback(operation, bundle)
            elif action == 'load': self.load()
            else: raise ValueError('unknown firewall operation')
        finally:
            os.close(fd)


if __name__ == '__main__':
    os.umask(0o077)
    try:
        Firewall(sys.argv[1]).dispatch(*sys.argv[2:])
    except (ValueError, KeyError, OSError, TypeError, subprocess.SubprocessError):
        print('RPC firewall operation refused: operation, bundle, rules or ownership differ', file=sys.stderr)
        sys.exit(1)
