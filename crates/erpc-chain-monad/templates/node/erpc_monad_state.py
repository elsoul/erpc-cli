# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Durable cancellation is published before any fallible mutation or shutdown."""
from pathlib import Path
from erpc_monad_common import Refused, atomic, json_bytes, read, remove, require, token, unique_json


class State:
    def __init__(self, directory):
        self.directory = directory

    def get(self, name):
        return unique_json(read(self.directory / name))

    def put(self, name, value):
        atomic(self.directory / name, json_bytes(value))

    def marker(self, name):
        atomic(self.directory / name, b'revoked\n')

    def check(self, contract):
        owner = self.get('owner.json')
        require(owner['contract'] == contract, 'remote immutable Monad contract differs')
        return owner

    def authorize(self, contract, intent, target):
        self.check(contract)
        token(intent)
        # Even a failure publishing the next intent must invalidate the old one.
        self.put('activation-revoked', {'intent': intent})
        self.put('operation.json', {'intent': intent, 'target': target})
        return intent

    def current(self, contract, intent):
        self.check(contract)
        current = self.get('operation.json')
        require(current['intent'] == token(intent), 'operation was cancelled or superseded')
        if (self.directory / 'activation-revoked').exists():
            require(self.get('activation-revoked') == {'intent': intent},
                    'another authorization revoked this operation before its publication')
        require(not (self.directory / 'retired').exists() and not (self.directory / 'stopped').exists(),
                'operation was explicitly stopped or retired')
        return current

    def begin(self, contract, intent, target, stop):
        operation = self.get('operation.json')
        self.check(contract)
        require(operation == {'intent': token(intent), 'target': target}, 'operation target was superseded')
        require(self.get('activation-revoked') == {'intent': intent},
                'preparation requires its own durable authorization receipt')
        if (self.directory / 'installed.json').exists():
            old = self.get('installed.json')['operation']['target']
            if 'version' in old:
                require(tuple(map(int, target['version'].split('.'))) >= tuple(map(int, old['version'].split('.'))),
                        'native downgrade is refused')
                require(target['version'] != old['version'] or target == old,
                        'same-version source substitution is refused')
        pending = self.directory / 'installing.json'
        if pending.exists():
            require(self.get('installing.json')['target'] == target,
                    'resume the previously interrupted target before selecting another')
        self.put('activation-revoked', {'intent': intent})
        self.put('installing.json', operation)
        # Explicitly authorizing a fresh deployment can recover a stopped or
        # retired incomplete install, but never removes the installing fence.
        remove(self.directory / 'stopped')
        remove(self.directory / 'retired')
        stop()
        return operation

    def finish(self, contract, intent, receipt):
        operation = self.current(contract, intent)
        require(self.get('installing.json') == operation, 'installing target no longer matches')
        self.put('installed.json', {'operation': operation, 'receipt': receipt})
        # Clear revoked first, while installing still prevents every startup.
        remove(self.directory / 'activation-revoked')
        remove(self.directory / 'installing.json')

    def cancel(self, contract, retired, stop):
        self.check(contract)
        cancellation_persisted = False
        try:
            self.marker('retired' if retired else 'stopped')
            self.marker('activation-revoked')
            # Earlier durable markers still revoke startup if this final write
            # fails. Failure of the very first marker has no such guarantee.
            self.put('operation.json', {'intent': None, 'target': None})
            cancellation_persisted = True
        except Exception:
            # Only after verifying ownership, attempt shutdown even when storage
            # cannot record the first fence. Do not expose raw storage errors.
            pass
        try:
            stop()
        except Exception:
            if not cancellation_persisted:
                raise Refused('durable cancellation and owned shutdown both failed; inspect the owned node') from None
            raise
        require(cancellation_persisted,
                'owned shutdown attempted but cancellation was not persisted; repair storage before relying on restart protection')

    def guard(self, contract, intent=None, manual=False):
        self.check(contract)
        require(not (self.directory / 'retired').exists()
                and not (self.directory / 'installing.json').exists(), 'node is retired or incomplete')
        installed = self.get('installed.json')
        if intent is not None:
            require(self.current(contract, intent) == installed['operation'], 'activation target differs')
        if manual:
            # The explicit manual-start command can clear an ordinary stop only
            # after caller verifies identity, device, native files and policy.
            require((self.directory / 'stopped').exists() and self.get('operation.json')['intent'] is None
                    and read(self.directory / 'activation-revoked') == b'revoked\n',
                    'manual start cannot supersede a pending deployment')
        else:
            require(not (self.directory / 'stopped').exists()
                    and not (self.directory / 'activation-revoked').exists(), 'startup authorization revoked')
        return installed

    def manual_ready(self, contract):
        self.guard(contract, manual=True)
        remove(self.directory / 'activation-revoked')
        remove(self.directory / 'stopped')

    def consume(self, contract, intent):
        self.current(contract, intent)
        self.put('operation.json', {'intent': None, 'target': None})
