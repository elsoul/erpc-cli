#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual controller dispatch/state paths with inert host/NSS/provider boundaries."""
from pathlib import Path
import os
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'templates/validator/node'))
sys.path.insert(0, str(ROOT.parent/'erpc-chain-rollup/templates/scripts'))
import control
import host
import protocol
import state
import storage


class Controller(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup); self.addCleanup(patch.stopall)
        self.root = Path(temp.name).resolve()
        patch.object(storage, 'ROOT_UID', os.getuid()).start(); patch.object(storage, 'TRUST_ANCHOR', self.root).start()
        patch.object(host, 'ROOT', self.root/'state').start(); patch.object(host, 'RUNTIME', self.root/'run').start()
        self.expected = {'owner': 'a'*26, 'family': 'arbitrum', 'network': 'mainnet', 'platform': 'amd64',
                         'role': 'assertion-validator', 'wallet': '0x'+'1'*40, 'creation': 'b'*32,
                         'host_binding': 'c'*64, 'data_uuid': '00000000-0000-0000-0000-000000000001'}
        storage.directory(host.ROOT, create=True)
        self.controller = control.Control(self.expected); self.controller.state.reserve(self.expected)
        self.target = {'phase': 'observing', 'version': protocol.VERSION, 'commit': protocol.COMMIT,
                       'image': protocol.IMAGE, 'image_id': protocol.IMAGE_ID, 'helpers_sha256': 'a'*64, 'config_id': 'b'*64}
        patch.object(host, 'namespaces').start(); patch.object(host, 'capacity').start()
        patch.object(control.accounts, 'verify', return_value={'node': {'uid':20000, 'gid':20000}}).start()
        patch.object(control.container, 'image').start()
        patch.object(control.publication, 'profile', return_value=('a'*64, {})).start()
        self.stops = []
        patch.object(control.Control, 'shutdown', side_effect=lambda: self.stops.append('owned shutdown')).start()

    def request(self, action, **fields): return dict(action=action, contract=self.expected, **fields)

    def test_actual_stop_dispatch_first_write_failure_fences_all_old_credential_and_activation_paths(self):
        self.controller.prepare('d'*32, self.target)
        original = self.controller.state.get('pending.json')
        real = state.State.put
        def failure(owned, name, value):
            if name == 'fence.json': raise OSError('inert failed first persistent write')
            real(owned, name, value)
        with patch.object(state.State, 'put', failure), self.assertRaises(OSError): control.dispatch(self.request('stop'))
        self.assertEqual(self.controller.state.get('pending.json'), original)
        self.assertEqual(len(self.stops), 2)
        with patch.object(control.runtime, 'common') as firewall:
            with self.assertRaisesRegex(ValueError, 'cancelled'):
                control.dispatch(self.request('firewall-confirm', intent='d'*32, operation='r-test-1', bundle='e'*64))
            firewall.assert_not_called()
        with self.assertRaisesRegex(ValueError, 'cancelled'):
            control.dispatch(self.request('import-wallet', intent='d'*32, secret='inert-not-a-key', restore=False))
        with self.assertRaisesRegex(ValueError, 'cancelled'):
            control.dispatch(self.request('import-upstreams', intent='d'*32, secret='inert-not-a-credential'))
        self.assertFalse((host.ROOT/'key-origin.json').exists())
        with self.assertRaisesRegex(ValueError, 'cancelled'):
            self.controller.state.activate(self.expected, 'd'*32, lambda _: None)
        self.controller.prepare('f'*32, self.target)
        self.controller.state.activate(self.expected, 'f'*32, lambda _: None)
        self.assertEqual(self.controller.state.guard(self.expected), self.target)

    def test_same_network_foreign_inventory_cannot_reach_shutdown_or_host_checks(self):
        foreign = dict(self.expected, owner='z'*26)
        for action in ('stop', 'destroy', 'start', 'restart'):
            with self.assertRaisesRegex(ValueError, 'original validator'): control.dispatch({'action':action, 'contract':foreign})
        self.assertEqual(self.stops, [])

    def test_future_installed_catalog_and_unfunded_active_transition_refuse_before_draining(self):
        self.controller.state.put('active.json', {'target':dict(self.target, version='4.0.0'), 'generation':'e'*32})
        with self.assertRaisesRegex(ValueError, 'catalog'): self.controller.prepare('d'*32, self.target)
        self.assertEqual(self.stops, [])
        self.controller.state.put('active.json', {'target':self.target, 'generation':'e'*32})
        with patch.object(control.Control, 'parent_observation', return_value={'funding_checks_passed':False}):
            with self.assertRaisesRegex(ValueError, 'funding'): self.controller.prepare('d'*32, dict(self.target, phase='active'))
        self.assertEqual(self.stops, [])

    def test_start_is_idempotent_for_an_already_proved_original_runtime(self):
        self.controller.prepare('d'*32,self.target)
        self.controller.state.activate(self.expected,'d'*32,lambda _:None)
        self.controller.state.put('container.json',{'inert':'original container fixture'})
        before=self.controller.state.fence(); self.stops.clear()
        with patch.object(control.services,'transport'), patch.object(control.services,'running'), \
             patch.object(control.container,'prove'), patch.object(control.Control,'observe',return_value={
                 'phase':'observing','local_validation_ready':True,'validator_ready':False}):
            result=self.controller.start()
        self.assertTrue(result['already_running']);self.assertEqual(self.stops,[])
        self.assertEqual(self.controller.state.fence(),before)

    def test_watcher_health_is_never_reported_as_active_validator_ready(self):
        with patch.object(control.Control, 'observe', return_value={'phase':'observing', 'local_validation_ready':True,
                                                                  'validator_ready':False}):
            value = control.dispatch(self.request('status'))
        self.assertTrue(value['local_validation_ready']); self.assertFalse(value['ready'])
        self.assertFalse(value['validator_ready']); self.assertTrue(value['problems'])

    def test_unknown_status_returns_failure_observation_without_provider_or_secret_diagnostics(self):
        with patch.object(control.Control, 'observe', side_effect=RuntimeError('INERT_PRIVATE_PROVIDER_MARKER')):
            value = control.dispatch(self.request('status'))
        self.assertFalse(value['ready']); self.assertNotIn('INERT_PRIVATE_PROVIDER_MARKER', str(value))


if __name__ == '__main__': unittest.main()
