# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Deployment cancellation is independent of the last approved running release.

A long source build cannot hold the node-operation lock. Its continuation must
match both the latest intent fence and the halt generation captured at request
creation. Only cutover blocks the currently approved runtime; stop revokes both.
"""
from pathlib import Path
import re
import secrets
from native_files import Refused, atomic, encoded, json_value, read, require, sync_directory, sync_file


def token(value):
    require(isinstance(value, str) and re.fullmatch('[a-f0-9]{32}', value), 'invalid operation identity')
    return value


class State:
    def __init__(self, directory, migration=None):
        self.directory = directory
        self.migration = migration

    def migration_scope(self, contract, owner=None):
        """A pending original copy may never be treated as fresh empty data.

        Only the migration coordinator passes the exact independently bound
        scope. Ordinary controllers require a completed promotion marker. The
        additional owner field also makes old init helpers refuse this format.
        """
        path=self.directory/'migration.json'
        expected=self.migration
        if owner is not None and 'migration' in owner:
            require(expected is None or owner['migration']==expected,'original migration owner differs')
            expected=owner['migration']
        if expected is None:
            require(not path.exists() and not path.is_symlink(),'unrecorded migration marker cannot be adopted')
            return None
        require(isinstance(expected,dict) and set(expected)=={'intent','source_sha256'}
                and isinstance(expected['source_sha256'],str) and re.fullmatch('[a-f0-9]{64}',expected['source_sha256']),
                'invalid original migration scope')
        token(expected['intent'])
        marker=self.get(path.name)
        require(isinstance(marker,dict) and set(marker)=={'contract','scope','phase'} and marker['contract']==contract
                and marker['scope']==expected and marker['phase'] in ('preparing','complete'),
                'original native migration marker differs')
        require(self.migration is not None or marker['phase']=='complete','original copy promotion is incomplete')
        if owner is not None:require(owner.get('migration')==expected,'native owner lacks its original migration binding')
        return expected

    def get(self, name):
        return json_value(read(self.directory / name, 1048576))

    def put(self, name, value):
        atomic(self.directory / name, encoded(value))

    def remove(self, name):
        (self.directory / name).unlink(missing_ok=True)
        sync_directory(self.directory)

    def reserve(self, contract):
        """Caller validates an otherwise clean dedicated host before this write."""
        path = self.directory / 'owner.json'
        if not path.exists():
            migration=self.migration_scope(contract)
            if migration is not None:
                sync_file(self.directory/'migration.json');sync_directory(self.directory)
            allowed={'migration.json'} if migration is not None else set()
            require(all(item.name in allowed or migration is not None and re.fullmatch(r'\.erpc-[a-f0-9]{32}',item.name)
                        for item in self.directory.iterdir()),'unowned native lifecycle state exists')
            owner={'contract':contract,'initial_halt':secrets.token_hex(16),'initialized':False}
            if migration is not None:owner['migration']=migration
            self.put('owner.json',owner)
        owner = self.get('owner.json')
        migration=self.migration_scope(contract,owner)
        require(set(owner) == ({'contract','initial_halt','initialized','migration'} if migration is not None else {'contract', 'initial_halt', 'initialized'})
                and type(owner['initialized']) is bool and owner['contract'] == contract,
                'immutable host contract differs')
        if not owner['initialized']:
            # Nothing may install keys, build or run before reserve completes.
            allowed={'owner.json','halt.json','intent-fence.json'}|({'migration.json'} if migration is not None else set())
            require(all(path.name in allowed
                        or re.fullmatch(r'\.erpc-[a-f0-9]{32}', path.name)
                        for path in self.directory.iterdir()), 'incomplete initialization has unexpected state')
            halt = {'generation': token(owner['initial_halt']), 'retired': False}
            fence = {'intent': None, 'halt': halt['generation']}
            for name, expected in [('halt.json', halt), ('intent-fence.json', fence)]:
                if (self.directory / name).exists():
                    require(self.get(name) == expected, 'interrupted initialization differs')
                else:
                    self.put(name, expected)
            self.put('owner.json', dict(owner, initialized=True))
        self.owner(contract)
        self.halt()
        self.get('intent-fence.json')

    def owner(self, contract):
        value = self.get('owner.json')
        self.migration_scope(contract,value)
        require(value['contract'] == contract and value['initialized'] is True,
                'host ownership differs or initialization is incomplete')
        return value

    def halt(self):
        value = self.get('halt.json')
        require(set(value) == {'generation', 'retired'} and type(value['retired']) is bool,
                'invalid halt generation')
        token(value['generation'])
        return value

    def authorize(self, contract, intent, target, action):
        self.owner(contract)
        self.recovery_clear(contract)
        token(intent)
        require(not any((self.directory / (prefix + intent + '.json')).exists()
                        for prefix in ('recovered-cutover-', 'abandoned-build-')),
                'a recovered or abandoned intent is permanently canceled; create a fresh deployment')
        require(action in ('deploy', 'update', 'update-config', 'activate-validator'), 'unsupported deployment request')
        halt = self.halt()
        if halt['retired'] and not self.runtime_is_current():
            require(action == 'deploy', 'retired node requires an explicit deploy')
        # Persist the new intent before publishing the rest of the request.
        # A failure in that later write must never revive the previous request.
        fence = {'intent': intent, 'halt': halt['generation']}
        self.put('intent-fence.json', fence)
        pending = dict(fence, target=target, action=action)
        self.put('pending.json', pending)
        return pending

    def current(self, contract, intent):
        self.owner(contract)
        self.recovery_clear(contract)
        fence = {'intent': token(intent), 'halt': self.halt()['generation']}
        require(self.get('intent-fence.json') == fence, 'deployment was cancelled or superseded')
        pending = self.get('pending.json')
        require(pending['intent'] == intent and pending['halt'] == fence['halt'], 'pending deployment differs')
        return pending

    def runtime_is_current(self):
        return ((self.directory / 'active.json').exists()
                and self.get('active.json')['halt'] == self.halt()['generation'])

    def guard(self, contract):
        self.owner(contract)
        self.recovery_clear(contract)
        require(not (self.directory / 'cutover.json').exists(), 'runtime cutover is incomplete')
        active = self.get('active.json')
        require(active['halt'] == self.halt()['generation'], 'runtime is explicitly stopped or retired')
        return active

    def begin(self, contract, intent, stop):
        pending = self.current(contract, intent)
        path = self.directory / 'cutover.json'
        previous = self.get('active.json') if (self.directory / 'active.json').exists() else None
        if path.exists():
            old = self.get('cutover.json')
            require(old['target'] == pending['target'], 'resume the incomplete cutover target first')
            previous = old['previous']
        self.put('cutover.json', {'intent': intent, 'halt': pending['halt'],
                                 'target': pending['target'], 'previous': previous})
        stop()
        return pending

    def publish(self, contract, intent, receipt):
        pending = self.current(contract, intent)
        cutover = self.get('cutover.json')
        require(all(cutover[k] == pending[k] for k in ('intent', 'halt', 'target')), 'cutover no longer owns this target')
        active = {'intent': intent, 'halt': pending['halt'], 'target': pending['target'], 'receipt': receipt}
        self.put('active.json', active)
        halt = self.halt()
        if halt['retired']:
            require(pending['action'] == 'deploy', 'only explicit deployment can unretire a node')
            # Keep cutover closed until both the approved runtime and the
            # retirement transition are durable. A failed retry remains stopped.
            self.put('halt.json', dict(halt, retired=False))
        # If this durable removal fails, do not request systemd startup.
        self.remove('cutover.json')
        return active

    def consume(self, contract, intent):
        pending = self.current(contract, intent)
        require(self.guard(contract)['intent'] == intent, 'runtime belongs to another deployment')
        self.put('intent-fence.json', {'intent': None, 'halt': pending['halt']})
        self.remove('pending.json')

    def stop(self, contract, shutdown, retired=False):
        self.owner(contract)
        halt = {'generation': secrets.token_hex(16), 'retired': bool(retired)}
        # This first write independently revokes runtime AND old build continuations.
        try:
            self.put('halt.json', halt)
            self.put('intent-fence.json', {'intent': None, 'halt': halt['generation']})
        except Exception:
            # Storage failure must not prevent best-effort owned shutdown.
            # The caller still receives a failure: durable cancellation has not
            # been established merely because the shutdown callback returned.
            try:
                shutdown()
            except Exception:
                raise Refused('cancellation could not be persisted and owned shutdown also failed') from None
            raise
        shutdown()
        return halt

    def manual_start(self, contract, qualify):
        self.owner(contract)
        self.recovery_clear(contract)
        require(not (self.directory / 'cutover.json').exists(), 'resume the incomplete deployment before starting')
        halt = self.halt()
        active = self.get('active.json')
        if active['halt'] == halt['generation']:
            qualify(active)
            return active
        require(not halt['retired'], 'manual start cannot unretire a node')
        require(self.get('intent-fence.json') == {'intent': None, 'halt': halt['generation']},
                'manual start cannot erase a pending or incompletely published deployment')
        qualify(active)
        active = dict(active, halt=halt['generation'])
        self.put('active.json', active)
        return active

    def recovery_clear(self, contract):
        path = self.directory / 'cutover-recovery.json'
        if path.exists():
            record = self.get(path.name)
            require(record.get('contract') == contract and record.get('phase') == 'complete',
                    'complete the original explicit cutover recovery before another operation')
            sync_file(path); sync_directory(self.directory)
