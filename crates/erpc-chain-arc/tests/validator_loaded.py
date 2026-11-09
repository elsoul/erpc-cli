#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Generated policy -> actual loaded proof/condition/start/stop, no real credentials.

NSS, artifact qualification and PID1 are inert capabilities. Unit publication,
receipts, typed D-Bus decoding, policy comparison and lifecycle entrypoints are
production code. The fixture is author-written, not a reviewer reproduction.
"""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import shlex
import runpy
import sys
import tempfile
import types
import unittest
from unittest import mock

sys.dont_write_bytecode = True
TESTS = Path(__file__).parent
sys.path.insert(0, str(TESTS))
import validator_loaded_model as model
TEMPLATES = TESTS.parent / 'templates'
sys.path[:0] = [str(TEMPLATES / 'validator'), str(TEMPLATES / 'authority')]
import av_state
import av_events
import av_units
import av_process
from arc_files import Refused
from av_files import ROOT


class Loaded(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.folder = self.root / 'bundle/validator'
        shutil.copytree(TEMPLATES / 'validator', self.folder)
        for name in ('arc_files.py', 'arc_release.py', 'arc_process.py', 'arc_trust.py', 'arc_helper_release.py'):
            shutil.copy(TEMPLATES / 'authority' / name, self.folder / name)
        shutil.copy(TESTS.parents[1] / 'erpc-ops/templates/rpc-firewall.py', self.folder.parent / 'rpc-firewall.py')
        spec = importlib.util.spec_from_file_location('actual_loaded_controller', self.folder / 'control.py')
        self.module = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.module)
        self.context = self.module.Controller(self.root, owner=os.getuid())
        self.context.mkdir(ROOT); self.context.mkdir('/etc/systemd/system', 0o755)
        self.context.mkdir('/usr/local/lib/erpc', 0o755)
        network = av_state.NETWORKS['testnet']
        self.contract = {'owner': 'a' * 26, 'network': 'testnet', 'chain_id': network['chain_id'],
                         'genesis_hash': network['genesis_hash'],
                         'public_key': '11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=',
                         'peer_public_key': 'PUAXw+hDiVqStwqnTRt+vJyYLM8uxJaMwM1V8Sr0Zgw=',
                         'controller': '0x' + 'b' * 40, 'host_binding': 'c' * 64}
        self.state = {'schema': 'erpc-arc-validator-v1', 'contract': self.contract,
                      'accounts': {'execution': 991, 'consensus': 992, 'engine': 993, 'established': True},
                      'phase': 'reserved', 'signer_used': False}
        self.target = {'version': 'v0.8.1', 'commit': self.module.arc_release.QUALIFIED_COMMIT,
                       'archive_sha256': self.module.arc_release.QUALIFIED_ARCHIVES['x86_64-unknown-linux-gnu'],
                       'platform': 'x86_64-unknown-linux-gnu'}
        self.policy = {'phase': 'observer', 'approved': False, 'fee_recipient': '0x' + 'b' * 40,
                       'execution_peers': [], 'sentry_peers': [], 'management_allow': [], 'monitoring_allow': [], 'ssh_port': 22}
        self.calls, self.records = [], {}
        self.context.command = self.command
        self.context.stop_original = mock.Mock(); self.context.assert_all_quiescent = mock.Mock()
        self.context.save(self.state)
        av_state.authorize(self.context, self.state, '1' * 32, self.target, self.policy)
        av_state.begin(self.context, self.state, '1' * 32)
        identity = self.module.av_helpers.source(self.context, self.folder)[2]
        self.module.dispatch(self.context, {'action': 'prepare-firewall', 'contract': self.contract,
            'intent': '1' * 32, 'helper_hash': identity}, self.folder)
        self.state = self.context.json(av_state.OWNER, private=True)
        source = {'images': {name: 'a' * 64 for name in ('arc-node-execution', 'arc-node-consensus', 'arc-snapshots')}}
        with mock.patch.object(av_units.release, 'qualify', return_value=source):
            texts, runtime = av_units.make(self.context, self.state, self.target, self.policy, self.folder, identity)
        av_units.publish(self.context, self.state, texts, runtime, self.target)
        self.state.update({'phase': 'installed', 'bootstrap_complete': True, 'source_floor': self.target})
        self.context.save(self.state)
        self.guard = self.context.firewall_guard_config()
        for component, unit in av_process.UNITS.items():
            directory = '/etc/systemd/system/' + unit + '.d'
            self.context.mkdir(directory, 0o755)
            self.context.write_bytes(directory + '/50-erpc-firewall-guard.conf', self.guard.encode(), 0o644)
            self.records[unit] = model.model(unit, texts[component], self.guard)
        firewall = 'erpc-arc-validator-firewall.service'
        self.records[firewall] = model.model(firewall, self.context.read('/etc/systemd/system/' + firewall).decode())
        self.context.assert_native_start = mock.Mock()
        self.context.confirmed_ingress = mock.Mock(); self.context.firewall = mock.Mock()
        self.accounts = mock.patch.object(self.module.av_accounts, 'verify'); self.accounts.start(); self.addCleanup(self.accounts.stop)
        self.secret = mock.patch.object(self.module.av_custody, 'verified'); self.custody = self.secret.start(); self.addCleanup(self.secret.stop)

    def command(self, *args, **kwargs):
        self.calls.append(args)
        if args[0] == '/usr/bin/busctl': return model.reply(args, self.records)
        if args[:2] == ('/usr/bin/systemctl', 'show'):
            return types.SimpleNamespace(returncode=0, stdout=b'LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\nControlGroup=\nExecMainStatus=0\nResult=success\n')
        return types.SimpleNamespace(returncode=0, stdout=b'')

    def starting(self):
        self.state['phase'] = 'starting'; self.context.save(self.state); self.context.remove(av_state.HALT)

    def test_real_generated_unit_and_boot_condition_accept_typed_original_policy(self):
        for component in av_process.UNITS:
            av_units.proof(self.context, self.state, component)
        self.starting()
        self.assertTrue(self.module.boot(self.context, 'condition', 'consensus')['original_credential'])
        self.custody.assert_called_once()
        self.assertTrue(all('get-property' in call for call in self.calls if call[0] == '/usr/bin/busctl'))

    def test_loaded_drift_refuses_before_custody_read_at_condition_and_before_enable(self):
        unit = av_process.UNITS['consensus']
        original = copy.deepcopy(self.records[unit])
        mutations = [
            ('Service', 'User', '0'), ('Service', 'Group', '0'), ('Service', 'SupplementaryGroups', ['992', '993', '0']),
            ('Service', 'DynamicUser', True), ('Service', 'RootImage', '/foreign'),
            ('Service', 'Environment', ['RUST_LOG=debug']),
            ('Service', 'LoadCredentialEncrypted', [['arc-validator-key', '/foreign']]),
            ('Service', 'LoadCredential', [['other', '/foreign']]),
            ('Service', 'ImportCredential', ['*']), ('Service', 'SetCredential', [['other', [1, 2]]]),
            ('Unit', 'DropInPaths', ['/run/systemd/system/foreign.conf']), ('Unit', 'OnFailure', ['foreign.service'])]
        extra = ['/inert-unknown', ['/inert-unknown'], [], 0, 0, 0, 0, 0, 0, 0]
        mutations += [('Service', command + 'Ex', [extra]) for command in model.COMMANDS]
        self.starting()
        for interface, field, value in mutations:
            self.records[unit] = copy.deepcopy(original)
            self.records[unit][interface][field]['data'] = value
            self.custody.reset_mock(); before = len(self.calls)
            with self.subTest(field=field), self.assertRaises(Refused):
                self.module.boot(self.context, 'condition', 'consensus')
            self.custody.assert_not_called()
            # The disk proof and loaded proof are the same pre-enable boundary.
            with self.assertRaises(Refused): av_units.proof(self.context, self.state, 'consensus')
            self.assertFalse(any(call[:2] == ('/usr/bin/systemctl', 'enable') for call in self.calls[before:]))
        self.records[unit] = original

    def test_unknown_loaded_stop_hook_is_never_executed_but_original_pid_drain_is_attempted(self):
        unit = av_process.UNITS['consensus']
        self.records[unit]['Service']['ExecStopEx']['data'] = [['/inert-foreign-hook', ['/inert-foreign-hook'], [], 0, 0, 0, 0, 0, 0, 0]]
        self.calls.clear()
        with mock.patch.object(av_process, 'signal_owned') as drain, \
             mock.patch.object(av_process, 'candidates', return_value=[]):
            with self.assertRaises(Refused):
                av_process.stop(self.context, self.state, {'consensus'}, [self.state['runtime']])
            drain.assert_called_once()
        self.assertFalse(any(call[:3] == ('/usr/bin/systemctl', 'stop', unit) for call in self.calls))

    def test_actual_generated_condition_refuses_loaded_drift_before_modeled_credential_grant(self):
        self.starting()
        unit = av_process.UNITS['consensus']
        text = self.context.read('/etc/systemd/system/' + unit).decode()
        line = next(line.split('=', 1)[1][1:] for line in text.splitlines() if line.startswith('ExecCondition='))
        argv = shlex.split(line)
        self.assertEqual(argv[:3], ['/usr/bin/python3', '-I', '-c'])
        program = argv[3]
        outer = bytes.fromhex(program.split("'", 2)[1]).decode()
        namespace = self.context.path('/usr/local/lib/erpc/arc-validator')
        outer = outer.replace('/usr/local/lib/erpc/arc-validator', str(namespace))
        real_lstat, real_scandir = os.lstat, os.scandir
        def metadata(path, *args, **kwargs):
            info = real_lstat(path, *args, **kwargs); fields = list(info)
            path = Path(path)
            if path == self.root or self.root in path.parents or path in self.root.parents:
                fields[4] = 0
                if path in self.root.parents: fields[0] &= ~0o022
            return os.stat_result(fields)
        def scanned(directory):
            with real_scandir(directory) as stream:
                return [types.SimpleNamespace(name=entry.name, path=entry.path,
                        stat=lambda *,follow_symlinks=True,p=entry.path:metadata(p)) for entry in stream]
        grants = []
        def enter(_path, **kwargs):
            self.assertEqual(sys.argv[1:], ['condition', 'consensus'])
            with mock.patch.object(os, 'lstat', real_lstat), mock.patch.object(os, 'scandir', real_scandir):
                result = self.module.boot(self.context, *sys.argv[1:])
            grants.append(result)  # Model v255 credential setup only after condition succeeds.
            return {}
        previous_argv = list(sys.argv)
        self.addCleanup(setattr, sys, 'argv', previous_argv)
        for changed in (True, False):
            self.records[unit]['Service']['User']['data'] = '0' if changed else '992'
            self.custody.reset_mock()
            with mock.patch.object(os, 'lstat', side_effect=metadata), mock.patch.object(os, 'scandir', side_effect=scanned), \
                 mock.patch.object(runpy, 'run_path', side_effect=enter):
                if changed:
                    with self.assertRaises(SystemExit) as error: exec(outer, {})
                    self.assertEqual(error.exception.code, 255)
                    self.assertFalse(grants); self.custody.assert_not_called()
                else:
                    exec(outer, {})
                    self.assertEqual(len(grants), 1); self.custody.assert_called_once()

    def test_explicit_start_checks_loaded_policy_before_enable_or_credential_read(self):
        unit = av_process.UNITS['consensus']
        self.records[unit]['Service']['Group']['data'] = '0'
        self.calls.clear(); self.custody.reset_mock()
        with self.assertRaises(Refused):
            self.module.observer_start(self.context, self.state, '1' * 32)
        self.custody.assert_not_called()
        self.assertFalse(any(call[:2] == ('/usr/bin/systemctl', 'enable') for call in self.calls))

    def test_untrusted_stop_policy_only_signals_revalidated_original_pid(self):
        unit = av_process.UNITS['consensus']; native = self.state['runtime']['consensus']
        self.records[unit]['Service']['ExecStopEx']['data'] = [['/foreign', ['/foreign'], [], 0, 0, 0, 0, 0, 0, 0]]
        owned = {'pid': 12345, 'start': '111', 'uids': ['992'] * 4, 'gids': ['992'] * 4,
                 'groups': ['992', '993'], 'argv': native['argv'], 'exe': str(self.context.path(native['binary'])),
                 'image': native['sha256'], 'cgroup': '/system.slice/' + unit}
        for foreign in (False, True):
            observed = copy.deepcopy(owned)
            if foreign: observed['uids'] = ['777'] * 4
            self.calls.clear()
            with mock.patch.object(av_process, 'candidates', side_effect=[[observed], [], []]), \
                 mock.patch.object(av_process, 'process', return_value=observed), \
                 mock.patch.object(av_process.os, 'pidfd_open', return_value=999, create=True) as opened, \
                 mock.patch.object(av_process.os, 'close'), \
                 mock.patch.object(av_process.signal, 'pidfd_send_signal', create=True) as sent:
                with self.assertRaises(Refused): av_process.stop(self.context, self.state, {'consensus'}, [self.state['runtime']])
                if foreign: opened.assert_not_called(); sent.assert_not_called()
                else: opened.assert_called_once_with(12345, 0); sent.assert_called_once()
            self.assertFalse(any(call[:3] == ('/usr/bin/systemctl', 'stop', unit) for call in self.calls))

    def test_bootstrap_and_firewall_loaded_commands_are_checked(self):
        for component in ('bootstrap', 'firewall'):
            unit = av_process.UNITS.get(component, 'erpc-arc-validator-firewall.service')
            old = copy.deepcopy(self.records[unit])
            self.records[unit]['Service']['ExecStartEx']['data'][0][1].append('foreign-argument')
            with self.assertRaises(Refused): self.context.unit_proof(self.state, component)
            self.records[unit] = old
            self.context.unit_proof(self.state, component)

    def test_typed_response_refuses_boolean_numbers_missing_or_malformed_properties(self):
        unit = av_process.UNITS['consensus']; original = copy.deepcopy(self.records[unit])
        for mutation in ('type', 'truncated-command', 'wrong-flags'):
            self.records[unit] = copy.deepcopy(original)
            if mutation == 'type': self.records[unit]['Service']['User']['type'] = 'u'
            if mutation == 'truncated-command': self.records[unit]['Service']['ExecStartEx']['data'][0].pop()
            if mutation == 'wrong-flags': self.records[unit]['Service']['ExecConditionEx']['data'][0][2] = []
            with self.assertRaises(Refused): av_units.proof(self.context, self.state, 'consensus')


if __name__ == '__main__': unittest.main()
