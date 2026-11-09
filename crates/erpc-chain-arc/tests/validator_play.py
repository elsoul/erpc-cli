#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Pinned Ansible templates -> actual compiled controller with inert host effects.

Supply validator_bundle's compiled JSON capture on stdin. This checks production
play fields/order and original controller state transitions. Package acquisition,
NSS, mount observations, native images, PID1 and snapshot data are explicitly
modeled; no host, node, signature or operational key is used.
"""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
from types import SimpleNamespace
from unittest import mock

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).parent))
import validator_loaded_model as loaded_model
from ansible import release
from ansible.parsing.dataloader import DataLoader
from ansible.template import Templar
from ansible.playbook.conditional import Conditional
assert release.__version__ == '2.18.19', 'use the hash-qualified repository Ansible runtime'
DOCUMENT = json.load(sys.stdin)
CA = '-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n'
INTENT = '1' * 32


class Fixture:
    def __enter__(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.bundle = self.root / 'opt/erpc/runs/r-inert-compiled/bundle'
        self.bundle.mkdir(parents=True)
        with tarfile.open(fileobj=io.BytesIO(bytes(DOCUMENT['bundle'])), mode='r:gz') as archive:
            for entry in archive.getmembers():
                path = self.bundle / entry.name
                assert entry.isfile() and path.resolve().is_relative_to(self.bundle)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(archive.extractfile(entry).read())
                path.chmod(0o644)
        self.folder = self.bundle / 'validator'
        sys.path.insert(0, str(self.folder))
        spec = importlib.util.spec_from_file_location('actual_arc_validator_controller', self.folder / 'control.py')
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.context = self.module.Controller(self.root, owner=os.getuid())
        self.context.mkdir(self.module.ROOT)
        self.context.mkdir('/etc/systemd/system', 0o755)
        self.context.mkdir('/usr/local/lib/erpc', 0o755)
        self.variables = next(iter(json.loads((self.bundle / 'inventory.yml').read_text())['all']['hosts'].values()))
        self.variables.update({'ansible_facts': {'distribution': 'Ubuntu', 'distribution_version': '24.04',
                              'architecture': 'x86_64', 'memtotal_mb': 64000}, 'arc_validator_ca': CA, 'arc_validator_intent': INTENT,
                              'erpc_fw_confirmed_run': 'r-inert-compiled', 'erpc_fw_confirmed_bundle': 'b' * 64,
                              'arc_submitted': {'stat': {'checksum': 'b' * 64}}})
        # This certificate-shaped value models publication, not TLS validity. The
        # separate public-fixture TLS tests exercise the actual trust handshake.
        self.variables['arc_validator_remote']['server_ca_sha256'] = hashlib.sha256(CA.encode()).hexdigest()
        self.variables['arc_validator_request'] = {'action': 'preflight'}
        self.calls = []
        self.loaded = {}
        self.context.command = lambda *args, **kwargs: self.record(args)
        self.context.stop_original = lambda _state: self.calls.append(('owned-stop',))
        self.context.disable_original = lambda _state: self.calls.append(('owned-disable',))
        self.context.assert_all_quiescent = lambda _state: self.calls.append(('quiescence',))
        self.context.assert_native_start = lambda _state, component: self.calls.append(('native-prestart', component))
        self.context.firewall = lambda *args: self.calls.append(('firewall', *args))
        self.stack = contextlib.ExitStack()
        self.stack.enter_context(mock.patch.object(self.module.av_accounts, 'reserve', return_value={
            'execution': 991, 'consensus': 992, 'engine': 993, 'established': False}))
        self.stack.enter_context(mock.patch.object(self.module.av_accounts, 'verify', return_value=None))
        self.stack.enter_context(mock.patch.object(self.module.av_accounts, 'provision', side_effect=self.accounts))
        self.stack.enter_context(mock.patch.object(self.module.av_storage, 'fresh', return_value={'filesystem': {'uuid': 'original', 'fstype': 'ext4'}}))
        self.stack.enter_context(mock.patch.object(self.module.av_storage, 'prepare', side_effect=self.storage))
        self.stack.enter_context(mock.patch.object(self.module.av_storage, 'verify', return_value=self.root / 'data'))
        self.stack.enter_context(mock.patch.object(self.module.av_storage, 'capacity', return_value={'inert': 'capacity'}))
        self.stack.enter_context(mock.patch.object(self.module.av_custody, 'verified', return_value=b'inert-original-ciphertext'))
        self.stack.enter_context(mock.patch.object(self.module.arc_release, 'install', side_effect=lambda *args: self.calls.append(('qualified-install',))))
        self.stack.enter_context(mock.patch.object(self.module.arc_release, 'qualify', return_value={
            'images': {name: 'a' * 64 for name in ('arc-node-execution', 'arc-node-consensus', 'arc-snapshots')}}))
        self.stack.enter_context(mock.patch.object(self.module.av_bootstrap, 'prepare', side_effect=self.prepare_snapshot))
        self.stack.enter_context(mock.patch.object(self.module.av_bootstrap, 'promote', side_effect=self.promote))
        return self

    def __exit__(self, *_):
        self.stack.close()
        sys.path.remove(str(self.folder))
        self.temporary.cleanup()

    def record(self, args):
        self.calls.append(args)
        if args[0] == '/usr/bin/busctl':
            self.refresh_loaded()
            return loaded_model.reply(args, self.loaded)
        return SimpleNamespace(returncode=0, stdout=b'', stderr=b'')

    def refresh_loaded(self):
        from av_process import UNITS
        from av_namespace import FIREWALL
        guard = self.context.firewall_guard_config()
        for unit in [*UNITS.values(), FIREWALL]:
            path = self.context.path('/etc/systemd/system/' + unit)
            if path.exists():
                if unit != FIREWALL:
                    destination = '/etc/systemd/system/' + unit + '.d'
                    self.context.mkdir(destination, 0o755)
                    self.context.write_bytes(destination + '/50-erpc-firewall-guard.conf', guard.encode(), 0o644)
                self.loaded[unit] = loaded_model.model(unit, path.read_text(), guard if unit != FIREWALL else None)

    def accounts(self, context, state):
        state['accounts']['established'] = True
        context.save(state)

    def storage(self, context, state):
        state['storage']['prepared'] = True
        context.save(state)

    def prepare_snapshot(self, context, state):
        state['directories'] = {'bootstrap': {'inode': 111}}
        context.save(state)

    def promote(self, context, state):
        state['bootstrap_complete'] = True
        state['phase'] = 'installed'
        context.save(state)
        return {'bootstrap': 'original-pair-promoted'}

    def state(self):
        return self.context.json(self.module.av_state.OWNER, private=True)

    def dispatch(self, action, **fields):
        request = {'action': action, 'contract': self.variables['arc_validator_contract'], **fields}
        return self.module.dispatch(self.context, request, self.folder)

    def play(self, name, stop_after=None):
        play = self.bundle / 'ansible/arc-validator' / (name + '.yml')
        data = DataLoader().load_from_file(str(play))
        self.variables['playbook_dir'] = str(play.parent)
        for task in data[0]['tasks']:
            if 'when' in task and not self.condition(task['when']):
                continue
            if 'ansible.builtin.assert' in task:
                for expression in task['ansible.builtin.assert']['that']:
                    if not self.condition(expression):
                        raise self.module.Refused('inert production Ansible assertion refused')
                continue
            command = task.get('ansible.builtin.command', {})
            if not isinstance(command, dict) or 'stdin' not in command:
                continue
            rendered = Templar(loader=DataLoader(), variables=self.variables).template(command, fail_on_undefined=True)
            argv = rendered['argv']
            assert argv[:3] == ['/usr/bin/python3', '-I', '-c']
            assert argv[3] == self.variables['arc_validator_loader']
            assert Path(argv[4]).resolve() == self.folder / 'control.py'
            value = json.loads(rendered['stdin'])
            result = self.module.dispatch(self.context, value, self.folder)
            self.calls.append(('request', value['action']))
            if 'register' in task:
                self.variables[task['register']] = {'stdout': json.dumps(result)}
            if value['action'] == 'bootstrap' and result['bootstrap'] != 'original-complete':
                # Source opening is claimed by the real generated boot guard,
                # before modeling native snapshot completion (no DB is opened).
                self.module.boot(self.context, 'guard', 'bootstrap')
                state = self.state()
                state['phase'] = 'bootstrap-complete'
                self.context.save(state)
            if 'until' in task:
                assert self.condition(task['until']), 'inert completion must release production polling'
            if value['action'] == stop_after:
                self.dispatch('stop')

    def condition(self, expression):
        check = Conditional(loader=DataLoader())
        check.when = [expression]
        return check.evaluate_conditional(Templar(loader=DataLoader(), variables=self.variables), self.variables)

    def authorize(self):
        self.dispatch('authorize', intent=self.variables['arc_validator_intent'], target=DOCUMENT['source'], policy=DOCUMENT['policy'])


for cancelled in (None, 'before-long', 'bootstrap'):
    with Fixture() as fixture:
        fixture.play('preflight')
        assert not fixture.context.path(fixture.module.av_state.OWNER).exists()
        fixture.play('init')
        fixture.authorize()
        fixture.play('firewall')
        fixture.dispatch('confirm-firewall', intent=INTENT, firewall_run='r-inert-compiled', firewall_bundle='b' * 64)
        if cancelled == 'before-long':
            fixture.dispatch('stop')
        before = len(fixture.calls)
        if cancelled:
            try:
                fixture.play('deploy', stop_after='bootstrap' if cancelled == 'bootstrap' else None)
            except fixture.module.Refused:
                pass
            else:
                raise AssertionError('cancelled compiled deployment must refuse')
            assert not any(call[:4] == ('/usr/bin/systemctl', 'enable', '--now', '--no-block')
                           for call in fixture.calls[before:])
        else:
            fixture.play('deploy')
            assert fixture.state()['phase'] == 'starting'
            assert fixture.state()['source_floor'] == DOCUMENT['source']
            assert any(call[:4] == ('/usr/bin/systemctl', 'enable', '--now', '--no-block') for call in fixture.calls)
            fixture.variables['arc_validator_intent'] = '2' * 32
            fixture.authorize()
            fixture.play('firewall')
            fixture.dispatch('confirm-firewall', intent='2' * 32, firewall_run='r-inert-compiled', firewall_bundle='b' * 64)
            fixture.play('deploy')
            assert fixture.variables['arc_bootstrap']['stdout'] == json.dumps({'bootstrap': 'original-complete'})
            fixture.play('destroy')
            assert fixture.context.path(fixture.module.av_state.RETIRED).exists()
            assert fixture.state()['source_floor'] == DOCUMENT['source']
with Fixture() as fixture:
    fixture.play('init')
    namespace = fixture.context.path('/usr/local/lib/erpc/arc-validator')
    import shutil
    shutil.rmtree(namespace / 'releases')
    fixture.variables['arc_validator_request'] = {'action': 'stop', 'contract': fixture.variables['arc_validator_contract']}
    fixture.play('control')
    assert ('owned-stop',) in fixture.calls
    before = len(fixture.calls)
    fixture.variables['arc_validator_request']['contract'] = dict(fixture.variables['arc_validator_contract'], owner='z' * 26)
    try:
        fixture.play('control')
    except fixture.module.Refused:
        pass
    else:
        raise AssertionError('carried stop must refuse a foreign original scope')
    assert len(fixture.calls) == before
print('all six compiled plays, original-complete retry and cancellation/carried-stop paths passed; native effects modeled')
