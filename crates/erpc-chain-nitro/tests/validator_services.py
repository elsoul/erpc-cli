#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Composed loaded-unit/original-account shutdown with inert process observations."""
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'templates/validator/node'))
sys.path.insert(0, str(ROOT.parent/'erpc-chain-rollup/templates/scripts'))
sys.path.insert(0, str(Path(__file__).parent))
from validator_container import Container
from validator_processes import Processes
import accounts
import control
import container
import host
import processes
import services
import state
import storage


class Services(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup); self.addCleanup(patch.stopall)
        self.root = Path(temp.name).resolve(); self.calls = []
        patch.object(storage, 'ROOT_UID', os.getuid()).start(); patch.object(storage, 'TRUST_ANCHOR', self.root).start()
        patch.object(host, 'ROOT', self.root/'state').start(); patch.object(host, 'RUNTIME', self.root/'run').start()
        patch.object(host, 'UNITS', self.root/'units').start(); host.UNITS.mkdir()
        patch.object(host, 'namespaces').start()
        self.proc = Processes(); self.proc.setUp(); self.addCleanup(self.proc.doCleanups)
        self.native = Container(); self.native.setUp()
        self.expected = self.native.contract
        self.controller = control.Control(self.expected, run=self.command)
        storage.directory(host.ROOT, create=True); self.controller.state.reserve(self.expected)
        self.records = {}
        for index, (role, (name, home)) in enumerate(accounts.SPECS.items()):
            self.records[role] = {'name':name, 'home':home, 'shell':accounts.SHELL, 'uid':20000+index, 'gid':20000+index}
        self.controller.state.put('accounts.json', {'contract':self.expected, 'accounts':self.records})
        self.loaded = {}
        self.existing = set()
        for role in ('node', 'transport'):
            path = host.UNITS/services.NAMES[role]; path.write_text('inert original '+role+' unit'); path.chmod(0o644)
            self.loaded[role] = {key:'' for key in services.FIXED}
            self.loaded[role].update(FragmentPath=str(path), User='0', Group='0', ExecStart='inert checked '+role)
        self.controller.state.put('units.json', {'contract':self.expected, 'units':{
            role:{'loaded':self.loaded[role], 'sha256':services.hashlib.sha256((host.UNITS/services.NAMES[role]).read_bytes()).hexdigest()}
            for role in self.loaded}})
        self.running = False
        self.native.value['State']['Pid'] = 234
        self.native.value['Mounts'][2]['Source'] = str(host.RUNTIME/'wallet/wallet.json')
        self.image = dict(self.native.image, Id=self.native.target['image_id'], Os='linux', Architecture='amd64',
                          RepoDigests=[self.native.target['image'].removeprefix('docker.io/')])
        self.revoke = patch.object(control.authority, 'revoke', side_effect=lambda group:self.calls.append(('revoke',group))).start()

    def command(self, argv, **kwargs):
        self.calls.append(tuple(argv))
        if argv[:2] == ['/usr/bin/systemctl', 'show']:
            role = next(role for role in self.loaded if services.NAMES[role] == argv[2])
            if role not in self.existing: return b'LoadState=not-found\n'
            return ('\n'.join(key+'='+value for key,value in dict(self.loaded[role], LoadState='loaded',
                       ActiveState='inactive', SubState='dead', MainPID='0').items())+'\n').encode()
        if argv[:2] == ['/usr/bin/systemctl', 'stop']: return b''
        if argv[0] == '/usr/bin/docker':
            args = argv[3:]
            if args[:2] == ['container','ls']: return (self.native.identity+'\n').encode() if self.running else b''
            if args[:2] == ['inspect','--type=image']: return json.dumps([self.image]).encode()
            if args[:2] == ['inspect','--type=container']: return json.dumps([self.native.value]).encode()
            if args[0] == 'stop':
                self.native.value['State'].update(Running=False, Pid=0)
                shutil.rmtree(self.proc.root/'234'); return b''
        raise AssertionError('unexpected inert host command '+repr(argv))

    def native_running(self):
        self.running = True
        self.proc.process()
        self.controller.state.put('container.json', dict(self.native.record, account=self.records['node']))

    def test_zero_partial_and_complete_unit_sets_preserve_repeatable_owned_stop(self):
        for existing in (set(), {'node'}, {'transport'}, {'node','transport'}):
            with self.subTest(existing=existing):
                self.existing = existing
                self.assertTrue(self.controller.stop()['stopped'])
                self.assertTrue(self.controller.stop()['stopped'])
        self.assertEqual(self.revoke.call_count, 8)

    def test_missing_unit_does_not_hide_an_original_native_container(self):
        self.native_running()
        self.assertTrue(self.controller.stop()['stopped'])
        self.assertFalse(self.native.value['State']['Running'])
        self.assertTrue(any('stop' in call and self.native.identity in call for call in self.calls))
        self.assertEqual(processes.owned_pids({20000}), set())

    def test_unknown_orphan_is_not_killed_and_prevents_success_after_known_container_drains(self):
        self.native_running(); self.proc.process(pid=235)
        (self.proc.root/'235/cgroup').write_text('0::/unknown-writer\n')
        with patch.object(services, 'time', SimpleNamespace(monotonic=iter([0,10]).__next__, sleep=lambda _:None)), self.assertRaises(ValueError): self.controller.stop()
        self.assertFalse((self.proc.root/'234').exists()); self.assertTrue((self.proc.root/'235').exists())
        self.assertTrue(self.controller.state.fence()['stopped'])

    def test_first_persistent_fence_failure_still_drains_using_retained_receipts_not_current_nss(self):
        self.native_running()
        with patch.object(accounts, 'verify', side_effect=ValueError('inert reassigned name')) as current_nss, \
             patch.object(self.controller.state, 'put', side_effect=OSError('inert persistent storage failure')):
            with self.assertRaises(OSError): self.controller.stop()
        self.assertFalse(self.native.value['State']['Running']); current_nss.assert_not_called()
        self.assertTrue((host.RUNTIME/'cancelled-state.json').exists())

    def test_unrelated_reused_transport_pid_is_not_signalled_or_confused_with_live_original(self):
        self.proc.process(pid=235,uid=30000,start=999)
        self.controller.state.put('transport-process.json',{'contract':self.expected,'account':self.records['transport'],
            'pid':235,'start_time':345,'executable':'/usr/bin/python3.12','argv':['inert original argv']})
        with patch.object(services,'terminate_transport',side_effect=AssertionError('must never signal reused PID')):
            self.assertTrue(self.controller.stop()['stopped'])
        self.assertTrue((self.proc.root/'235').exists())

    def test_condition_skip_or_wrong_loaded_recipient_never_counts_as_running(self):
        self.existing = {'node'}
        with self.assertRaisesRegex(ValueError, 'did not enter'): services.running(self.controller.state, self.expected, 'node', self.command)
        self.loaded['node']['User'] = '2001'
        with self.assertRaisesRegex(ValueError, 'recipient'): services.running(self.controller.state, self.expected, 'node', self.command)


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(Services)
    raise SystemExit(not unittest.TextTestRunner().run(suite).wasSuccessful())
